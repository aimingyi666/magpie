package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/access"
)

func decodeMachineJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	if !strings.HasSuffix(raw, "\n") || strings.Count(raw, "\n") != 1 {
		t.Fatalf("machine output must be one line and one newline: %q", raw)
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("machine output is not JSON: %v\n%s", err, raw)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("machine output has trailing JSON: %v\n%s", err, raw)
	}
	return out
}

func TestGatewayKeyMachineProtocol(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	secret, err := access.Update("add-key", access.Change{Name: "Employee laptop"})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := access.List()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	id, masked := keys[0].ID, keys[0].Masked

	call := func(policy any) (string, error) {
		t.Helper()
		body := ""
		if policy != nil {
			b, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			body = string(b)
		}
		var out bytes.Buffer
		err := gatewayKeysToInput(
			&out,
			[]string{"gateway-key", "policy", "apply", id, "--json"},
			strings.NewReader(body),
		)
		return out.String(), err
	}
	describe := func() (string, access.PolicyDescribe, error) {
		t.Helper()
		var out bytes.Buffer
		err := gatewayKeysToInput(
			&out,
			[]string{"gateway-key", "describe", id, "--json"},
			strings.NewReader(""),
		)
		var d access.PolicyDescribe
		if err == nil {
			err = json.Unmarshal(out.Bytes(), &d)
		}
		return out.String(), d, err
	}

	raw, before, err := describe()
	if err != nil {
		t.Fatal(err)
	}
	obj := decodeMachineJSON(t, raw)
	if obj["ok"] != true || obj["schemaVersion"] != float64(access.PolicySchemaVersion) {
		t.Fatalf("describe response %v", obj)
	}
	for _, forbidden := range []string{secret, masked} {
		if forbidden != "" && strings.Contains(raw, forbidden) {
			t.Fatalf("describe leaked %q: %s", forbidden, raw)
		}
	}

	raw, err = call(access.PolicyApply{
		SchemaVersion:          access.PolicySchemaVersion,
		ExpectedPolicyRevision: before.PolicyRevision,
		Models:                 []string{"openai/gpt-5.2", "anthropic/*"},
		Limits: []access.PolicyLimitInput{
			{Period: "month", Tokens: 5_000_000, Cost: 200},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var applied access.PolicyDescribe
	if err := json.Unmarshal([]byte(raw), &applied); err != nil {
		t.Fatal(err)
	}
	decodeMachineJSON(t, raw)
	if len(applied.Models.Patterns) != 2 ||
		applied.Models.Patterns[0] != "openai/gpt-5.2" ||
		applied.Models.Patterns[1] != "anthropic/*" ||
		len(applied.Limits) != 1 || applied.Limits[0].Tokens != 5_000_000 {
		t.Fatalf("apply response %+v", applied)
	}
	for _, forbidden := range []string{secret, masked} {
		if forbidden != "" && strings.Contains(raw, forbidden) {
			t.Fatalf("apply leaked %q: %s", forbidden, raw)
		}
	}

	raw, err = call(access.PolicyApply{
		SchemaVersion:          access.PolicySchemaVersion,
		ExpectedPolicyRevision: before.PolicyRevision,
		Models:                 []string{"openai/gpt-5.2"},
		Limits:                 []access.PolicyLimitInput{},
	})
	if err == nil {
		t.Fatal("stale policy revision was accepted")
	}
	failure := decodeMachineJSON(t, raw)
	if failure["ok"] != false {
		t.Fatalf("failure response %v", failure)
	}
	detail, ok := failure["error"].(map[string]any)
	if !ok || detail["code"] != access.PolicyErrPolicyConflict {
		t.Fatalf("failure response %v", failure)
	}
	for _, forbidden := range []string{secret, masked} {
		if forbidden != "" && strings.Contains(raw, forbidden) {
			t.Fatalf("failure leaked %q: %s", forbidden, raw)
		}
	}

	raw, err = call(nil)
	if err == nil {
		t.Fatal("empty policy input was accepted")
	}
	failure = decodeMachineJSON(t, raw)
	detail, ok = failure["error"].(map[string]any)
	if !ok || detail["code"] != access.PolicyErrOutputInvalid {
		t.Fatalf("invalid input response %v", failure)
	}
}
