package aws

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

const (
	stagedARN      = "arn:aws:secretsmanager:eu-south-1:123456789012:secret:origin-verify-AbCdEf"
	stagedCurrent  = "current-0f9e8d7c6b5a49382716051f2e3d4c5b"
	stagedPrevious = "previous-a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

// fakeStagedSecrets answers GetSecretValue per staging label, the way Secrets
// Manager does: a label attached to no version is ResourceNotFoundException.
type fakeStagedSecrets struct {
	mu      sync.Mutex
	stages  map[string]string // label -> SecretString
	binary  map[string]bool
	errs    map[string]error
	calls   []string // labels, in call order
	regions []string // the region each call was sent to, after optFns
}

func (f *fakeStagedSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var o secretsmanager.Options
	for _, fn := range optFns {
		fn(&o)
	}
	label := awssdk.ToString(in.VersionStage)
	f.calls = append(f.calls, label)
	f.regions = append(f.regions, o.Region)
	if awssdk.ToString(in.SecretId) != strings.Split(stagedARN, "#")[0] {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("Secrets Manager can't find the specified secret.")}
	}
	if err := f.errs[label]; err != nil {
		return nil, err
	}
	v, ok := f.stages[label]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("Secrets Manager can't find the specified secret value for staging label: " + label)}
	}
	if f.binary[label] {
		return &secretsmanager.GetSecretValueOutput{SecretBinary: []byte(v)}, nil
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: awssdk.String(v)}, nil
}

func stagesReader(api SecretsManagerAPI) *SecretStagesReader {
	return NewSecretStagesReader(SecretStagesReaderOptions{Client: api})
}

// TestSecretStagesReadsBothLabels: one GetSecretValue per label, AWSCURRENT
// first, each sent to the region the ARN names rather than the client's.
func TestSecretStagesReadsBothLabels(t *testing.T) {
	t.Parallel()
	api := &fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent, StagePrevious: stagedPrevious}}
	got, err := stagesReader(api).Read(t.Context(), stagedARN)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != (SecretStages{Current: stagedCurrent, Previous: stagedPrevious}) {
		t.Errorf("Read = %+v", got)
	}
	if strings.Join(api.calls, ",") != StageCurrent+","+StagePrevious {
		t.Errorf("labels read = %v, want AWSCURRENT then AWSPREVIOUS", api.calls)
	}
	for i, region := range api.regions {
		if region != "eu-south-1" {
			t.Errorf("call %d was sent to region %q, want the ARN's eu-south-1", i, region)
		}
	}
}

// TestSecretStagesIsNotCached: every Read reads again. That is the property the
// origin check's refresh depends on, and the one secretCache exists to deny the
// cold-start resolver.
func TestSecretStagesIsNotCached(t *testing.T) {
	t.Parallel()
	api := &fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent}}
	r := stagesReader(api)
	if _, err := r.Read(t.Context(), stagedARN); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	api.mu.Lock()
	api.stages = map[string]string{StageCurrent: "rotated-" + stagedCurrent, StagePrevious: stagedCurrent}
	api.mu.Unlock()
	got, err := r.Read(t.Context(), stagedARN)
	if err != nil {
		t.Fatalf("second Read: %v", err)
	}
	if got.Current != "rotated-"+stagedCurrent || got.Previous != stagedCurrent {
		t.Errorf("after a rotation Read = %+v: the reader answered from a cache", got)
	}
}

// TestSecretStagesWithoutAPreviousVersion: a secret never rotated has no
// AWSPREVIOUS label, and that is not a failure.
func TestSecretStagesWithoutAPreviousVersion(t *testing.T) {
	t.Parallel()
	got, err := stagesReader(&fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent}}).Read(t.Context(), stagedARN)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != (SecretStages{Current: stagedCurrent}) {
		t.Errorf("Read = %+v, want the current value and nothing else", got)
	}
}

// TestSecretStagesSelectsTheJSONKeyInBothVersions: the #jsonKey selector the
// other secret knobs take applies to each version.
func TestSecretStagesSelectsTheJSONKeyInBothVersions(t *testing.T) {
	t.Parallel()
	api := &fakeStagedSecrets{stages: map[string]string{
		StageCurrent:  `{"headerValue":"` + stagedCurrent + `","other":"x"}`,
		StagePrevious: `{"headerValue":"` + stagedPrevious + `"}`,
	}}
	got, err := stagesReader(api).Read(t.Context(), stagedARN+"#headerValue")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != (SecretStages{Current: stagedCurrent, Previous: stagedPrevious}) {
		t.Errorf("Read = %+v", got)
	}
}

// TestSecretStagesRefusals: what makes a read fail, and what only makes the
// previous value unusable. No message may carry a payload.
func TestSecretStagesRefusals(t *testing.T) {
	t.Parallel()
	denied := errors.New("AccessDeniedException: not authorized to perform secretsmanager:GetSecretValue")
	for _, tc := range []struct {
		name    string
		api     *fakeStagedSecrets
		ref     string
		wantErr string
		// wantProblem is set when Read succeeds and only the previous
		// version is unusable.
		wantProblem string
	}{
		{name: "no such secret", api: &fakeStagedSecrets{}, ref: strings.Replace(stagedARN, "origin-verify", "missing", 1), wantErr: "has no AWSCURRENT version"},
		{name: "current denied", api: &fakeStagedSecrets{errs: map[string]error{StageCurrent: denied}}, ref: stagedARN, wantErr: "AWSCURRENT failed"},
		{name: "current binary", api: &fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent}, binary: map[string]bool{StageCurrent: true}}, ref: stagedARN, wantErr: "binary value"},
		{name: "current empty", api: &fakeStagedSecrets{stages: map[string]string{StageCurrent: ""}}, ref: stagedARN, wantErr: "is empty"},
		{name: "current lacks the key", api: &fakeStagedSecrets{stages: map[string]string{StageCurrent: `{"other":"` + stagedCurrent + `"}`}}, ref: stagedARN + "#headerValue", wantErr: `has no key "headerValue"`},
		{name: "current is not JSON", api: &fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent}}, ref: stagedARN + "#headerValue", wantErr: "not a JSON object"},
		{
			name:    "previous denied",
			api:     &fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent}, errs: map[string]error{StagePrevious: denied}},
			ref:     stagedARN,
			wantErr: "AWSPREVIOUS failed",
		},
		{
			name:        "previous is not JSON",
			api:         &fakeStagedSecrets{stages: map[string]string{StageCurrent: `{"headerValue":"` + stagedCurrent + `"}`, StagePrevious: stagedPrevious}},
			ref:         stagedARN + "#headerValue",
			wantProblem: "not a JSON object",
		},
		{
			name:        "previous binary",
			api:         &fakeStagedSecrets{stages: map[string]string{StageCurrent: stagedCurrent, StagePrevious: stagedPrevious}, binary: map[string]bool{StagePrevious: true}},
			ref:         stagedARN,
			wantProblem: "binary value",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := stagesReader(tc.api).Read(context.Background(), tc.ref)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Read error = %v, want one saying %q", err, tc.wantErr)
				}
				for _, payload := range []string{stagedCurrent, stagedPrevious} {
					if strings.Contains(err.Error(), payload) {
						t.Errorf("the error names a payload: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got.Current != stagedCurrent || got.Previous != "" || !strings.Contains(got.PreviousProblem, tc.wantProblem) {
				t.Errorf("Read = %+v, want the current value, no previous and a problem saying %q", got, tc.wantProblem)
			}
			for _, payload := range []string{stagedCurrent, stagedPrevious} {
				if strings.Contains(got.PreviousProblem, payload) {
					t.Errorf("the problem names a payload: %s", got.PreviousProblem)
				}
			}
		})
	}
}
