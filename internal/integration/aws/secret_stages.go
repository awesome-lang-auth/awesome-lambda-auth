package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// The two staging labels a Secrets Manager rotation moves. Rotating a secret
// (PutSecretValue, or a rotation function's finishSecret step) attaches
// AWSCURRENT to the new version and moves AWSPREVIOUS to the version that held
// AWSCURRENT before it, so between them the two labels name the value a
// client is being moved to and the value it may still be sending.
//
// AWSPENDING is deliberately not read: it is a version a rotation is still
// testing, and accepting it would let a half-finished rotation open the door.
const (
	StageCurrent  = "AWSCURRENT"
	StagePrevious = "AWSPREVIOUS"
)

// SecretStages is one secret's value under AWSCURRENT and, once the secret has
// been rotated at least once, under AWSPREVIOUS. It carries no SDK type, so a
// caller's seam can be written against it without importing the AWS SDK —
// the posture IDPKeySource has for the KMS key.
type SecretStages struct {
	// Current is the value under AWSCURRENT, after the reference's #jsonKey
	// selector. Never empty: a reader that cannot produce one returns an error.
	Current string

	// Previous is the value under AWSPREVIOUS, or empty when there is none to
	// use: the secret has never been rotated, or the previous version holds no
	// usable value for the selector, in which case PreviousProblem says why.
	Previous string

	// PreviousProblem explains an AWSPREVIOUS version that exists and could
	// not be used — a binary value, not a JSON document, no such key. It
	// names the reference and never the payload.
	PreviousProblem string
}

// DefaultSecretStageTimeout bounds one GetSecretValue of a stage read.
//
// The read runs at cold start, inside cmd/auth's start timeout shared with
// everything else the init does, and again on a refresh interval inside a
// request. Two seconds is an order of magnitude above the p99 of an in-region
// GetSecretValue and leaves the rest of either budget room to fail with its
// own message.
const DefaultSecretStageTimeout = 2 * time.Second

// SecretStagesReaderOptions configures NewSecretStagesReader. The zero value
// is what the Lambda uses: the ambient credential chain, a real client built
// on first use, and DefaultSecretStageTimeout.
type SecretStagesReaderOptions struct {
	// Timeout bounds one GetSecretValue. Zero means DefaultSecretStageTimeout.
	Timeout time.Duration

	// Client injects a SecretsManagerAPI. Non-nil skips the lazy build.
	Client SecretsManagerAPI
}

// SecretStagesReader reads a secret under both of its rotation labels.
//
// It is the one Secrets Manager reader in this package that does NOT go
// through secretCache, and that is its reason to exist rather than a method on
// SecretsManagerResolver. The resolver serves knobs resolved once per
// execution environment, and its cache guarantees nothing turns them into a
// per-request call. A value that has to follow a rotation without the
// environment being recycled is the opposite case: its caller re-reads it on
// an interval of its own choosing (cmd/auth origin_verify.go, every five
// minutes), and a cache here would answer every one of those re-reads with
// the value the rotation retired.
type SecretStagesReader struct {
	client  *lazyClient[SecretsManagerAPI]
	timeout time.Duration
}

// NewSecretStagesReader builds the reader. It performs no I/O and cannot fail:
// the SDK client is built on the first Read.
func NewSecretStagesReader(opts SecretStagesReaderOptions) *SecretStagesReader {
	r := &SecretStagesReader{timeout: opts.Timeout}
	if r.timeout <= 0 {
		r.timeout = DefaultSecretStageTimeout
	}
	if opts.Client != nil {
		r.client = &lazyClient[SecretsManagerAPI]{
			build: func(context.Context) (SecretsManagerAPI, error) { return opts.Client, nil },
		}
		return r
	}
	shared := &lazyConfig{}
	r.client = &lazyClient[SecretsManagerAPI]{
		build: func(ctx context.Context) (SecretsManagerAPI, error) {
			cfg, err := shared.get(ctx)
			if err != nil {
				return nil, err
			}
			return secretsmanager.NewFromConfig(cfg), nil
		},
	}
	return r
}

// Read fetches ref — a Secrets Manager secret ARN, optionally followed by a
// #jsonKey selector (SecretRefKeySeparator) — under AWSCURRENT and then
// AWSPREVIOUS.
//
// Every failure to produce a current value is an error, and so is a previous
// version that exists and cannot be read: a denied or throttled read of it
// says nothing about whether the value a client sends is still good, so the
// caller has to decide what to do without it. A secret with no AWSPREVIOUS
// label at all is not a failure — it has simply never been rotated.
//
// The call is made in the region the ARN names, so a secret kept in another
// region than the function's is read where it lives. No error names a payload.
func (r *SecretStagesReader) Read(ctx context.Context, ref string) (SecretStages, error) {
	id, key := splitSecretRef(strings.TrimSpace(ref))
	if id == "" {
		return SecretStages{}, errors.New("secretsmanager: no secret ARN to read")
	}
	api, err := r.client.get(ctx)
	if err != nil {
		return SecretStages{}, fmt.Errorf("secretsmanager: cannot build a client for %q: %w", id, err)
	}

	current, err := r.stage(ctx, api, id, StageCurrent)
	if err != nil {
		return SecretStages{}, err
	}
	if current == nil {
		return SecretStages{}, fmt.Errorf("secretsmanager: secret %q has no %s version", id, StageCurrent)
	}
	value, err := stageValue(current, id, key, ref, StageCurrent)
	if err != nil {
		return SecretStages{}, err
	}
	stages := SecretStages{Current: value}

	previous, err := r.stage(ctx, api, id, StagePrevious)
	if err != nil {
		return SecretStages{}, err
	}
	if previous == nil {
		return stages, nil
	}
	if stages.Previous, err = stageValue(previous, id, key, ref, StagePrevious); err != nil {
		stages.Previous, stages.PreviousProblem = "", err.Error()
	}
	return stages, nil
}

// stage reads one labelled version. A nil output with a nil error means the
// label is attached to no version, which Secrets Manager reports as
// ResourceNotFoundException; for AWSCURRENT, Read turns that into an error.
func (r *SecretStagesReader) stage(ctx context.Context, api SecretsManagerAPI, id, label string) (*secretsmanager.GetSecretValueOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	out, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:     awssdk.String(id),
		VersionStage: awssdk.String(label),
	}, inRegionOf(id))
	if err != nil {
		var missing *smtypes.ResourceNotFoundException
		if errors.As(err, &missing) {
			return nil, nil
		}
		return nil, fmt.Errorf("secretsmanager: reading %q at %s failed: %w", id, label, err)
	}
	return out, nil
}

// stageValue applies the selector to one version's payload. A binary value is
// refused for the reason SecretsManagerResolver refuses one, and the payload is
// never quoted, for the reason selectFromPayload gives.
func stageValue(out *secretsmanager.GetSecretValueOutput, id, key, ref, label string) (string, error) {
	if out.SecretString == nil {
		return "", fmt.Errorf("secretsmanager: secret %q holds a binary value at %s, and this build reads SecretString only", id, label)
	}
	v, err := selectFromPayload(*out.SecretString, key, ref, "Secrets Manager secret")
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	return v, nil
}

// inRegionOf sends a call to the region an ARN names. An ARN is
// arn:partition:service:region:account:resource, and Secrets Manager answers a
// secret only from its own region's endpoint; anything that does not parse as
// one leaves the client's region alone.
func inRegionOf(id string) func(*secretsmanager.Options) {
	return func(o *secretsmanager.Options) {
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 && parts[0] == "arn" && parts[3] != "" {
			o.Region = parts[3]
		}
	}
}
