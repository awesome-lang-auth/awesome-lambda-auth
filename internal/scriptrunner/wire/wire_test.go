package wire

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// fixture reads one of the byte-level pins in testdata/. The runner's tests
// (internal/scriptrunner) and the invoker's (internal/integration/aws) read the
// same files by their path relative to this directory, so all three agree on
// one set of bytes rather than on three copies of it.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return bytes.TrimSpace(raw)
}

// TestRequestEncodesToThePinnedBytes: the invocation payload is the core's
// request with its own member names promoted to the top level, plus the
// deadline. A field renamed on either side, or the embedding turned into a
// nested member, changes these bytes.
func TestRequestEncodesToThePinnedBytes(t *testing.T) {
	t.Parallel()
	req := Request{
		InboundScriptRequest: auth.InboundScriptRequest{
			Provider:  "contract",
			WebhookID: "wh_1",
			Script:    "result = {event: 'identity.tenant.user.removed', data: body}",
			Body:      json.RawMessage(`{"id":"evt_1","amount":12,"nested":{"ok":true}}`),
			Actions:   []string{"user.suspend"},
		},
		DeadlineUnixMs: 1790000000000,
	}
	got, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := fixture(t, "request.json"); !bytes.Equal(got, want) {
		t.Errorf("request encodes as\n  %s\nwant\n  %s", got, want)
	}

	// And back: a runner decoding the pinned bytes sees the body raw, not
	// re-encoded, which is what lets a script see what the provider sent.
	var back Request
	if err := json.Unmarshal(fixture(t, "request.json"), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(back.Body) != `{"id":"evt_1","amount":12,"nested":{"ok":true}}` {
		t.Errorf("body decoded as %s; it must cross unmodified", back.Body)
	}
	if !reflect.DeepEqual(back, req) {
		t.Errorf("round trip = %+v, want %+v", back, req)
	}
}

// TestResponsesEncodeAndAnswerAsPinned is the table both sides of the wire
// share: each fixture, the Go value that encodes to it, and the core's answer
// it maps to.
func TestResponsesEncodeAndAnswerAsPinned(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		fixture  string
		value    Response
		emit     bool
		wantData map[string]any
	}{
		{
			fixture: "response-result.json",
			value: Response{Outcome: OutcomeResult, Result: &auth.InboundScriptResult{
				Event:    "identity.tenant.user.removed",
				Data:     map[string]any{"id": "evt_1", "amount": json.Number("12"), "nested": map[string]any{"ok": true}},
				UserID:   "u_1",
				TenantID: "t_1",
			}},
			emit: true,
			// Decoded by the invoker without UseNumber, as the core's own
			// decoders do: a number is a float64 on this side.
			wantData: map[string]any{"id": "evt_1", "amount": float64(12), "nested": map[string]any{"ok": true}},
		},
		{fixture: "response-none.json", value: Response{Outcome: OutcomeNone, Reason: ReasonNoResult}},
		{fixture: "response-threw.json", value: Response{Outcome: OutcomeNone, Reason: ReasonThrew}},
		{fixture: "response-never-settled.json", value: Response{Outcome: OutcomeNone, Reason: ReasonNeverSettled}},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if want := fixture(t, tc.fixture); !bytes.Equal(got, want) {
				t.Errorf("encodes as\n  %s\nwant\n  %s", got, want)
			}
			decoded, err := Decode(fixture(t, tc.fixture))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			result, emit, err := decoded.Answer()
			if err != nil {
				t.Fatalf("Answer: %v", err)
			}
			if emit != tc.emit {
				t.Fatalf("emit = %v, want %v", emit, tc.emit)
			}
			if !emit {
				if !reflect.DeepEqual(result, auth.InboundScriptResult{}) {
					t.Errorf("a no-result answer carried %+v; the core's contract is the zero value", result)
				}
				return
			}
			if result.Event != "identity.tenant.user.removed" || result.UserID != "u_1" || result.TenantID != "t_1" {
				t.Errorf("result = %+v", result)
			}
			if !reflect.DeepEqual(result.Data, tc.wantData) {
				t.Errorf("data = %#v, want %#v", result.Data, tc.wantData)
			}
		})
	}
}

// TestAnAnswerThisBuildDoesNotUnderstandIsAnError: never a silent "no
// result", because that would acknowledge a webhook on the runner's behalf.
func TestAnAnswerThisBuildDoesNotUnderstandIsAnError(t *testing.T) {
	t.Parallel()
	for _, payload := range []string{
		`{"outcome":"result"}`,
		`{"outcome":"maybe"}`,
		`{}`,
		`null`,
	} {
		r, err := Decode([]byte(payload))
		if err != nil {
			continue
		}
		if _, _, err := r.Answer(); err == nil {
			t.Errorf("%s answered without an error", payload)
		}
	}
	if _, err := Decode([]byte(`not json`)); err == nil || !strings.Contains(err.Error(), "not the runner's JSON") {
		t.Errorf("a non-JSON payload decoded: %v", err)
	}
}
