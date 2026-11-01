package access

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func policyTestNow(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	previous := Now
	Now = func() time.Time { return now }
	t.Cleanup(func() { Now = previous })
	return now
}

func policyTestKey(t *testing.T, now time.Time) (Key, string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := Update("add-key", Change{Name: "Employee laptop"}); err != nil {
		t.Fatal(err)
	}
	keys, err := load()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	keys[0].Accounts = []string{"acme/account-1", "acme/account-2"}
	keys[0].Models = []string{"openai/gpt-5.2"}
	keys[0].ReadOnly = true
	keys[0].Issuer = "issuer-fixture"
	keys[0].Expires = now.Add(24 * time.Hour)
	keys[0].Off = true
	keys[0].setLimits([]Limit{
		{Period: "hours", Hours: 5, Tokens: 1000, Since: now.Add(-2 * time.Hour)},
		{Period: "month", Cost: 20},
	})
	if err := save(keys); err != nil {
		t.Fatal(err)
	}
	return keys[0], keys[0].Secret
}

func policyCode(t *testing.T, err error) string {
	t.Helper()
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a PolicyError", err)
	}
	return pe.Code
}

func TestDecodePolicyApplySchemaV1(t *testing.T) {
	in, err := DecodePolicyApply(strings.NewReader(`{
		"schemaVersion": 1,
		"expectedPolicyRevision": "sha256:fixture",
		"models": ["openai/gpt-5.2", "anthropic/*"],
		"limits": [
			{"period":"month","tokens":5000000,"cost":200,"cacheReads":false}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if in.SchemaVersion != 1 || in.ExpectedPolicyRevision != "sha256:fixture" ||
		!slices.Equal(in.Models, []string{"openai/gpt-5.2", "anthropic/*"}) ||
		len(in.Limits) != 1 || in.Limits[0].Period != "month" ||
		in.Limits[0].Tokens != 5_000_000 || in.Limits[0].Cost != 200 {
		t.Fatalf("decoded %+v", in)
	}

	tests := []struct {
		name string
		body string
		code string
	}{
		{
			name: "unknown root field",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":[],"secret":"x"}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "duplicate root field",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"models":["a/c"],"limits":[]}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "missing field",
			body: `{"schemaVersion":1,"models":["a/b"],"limits":[]}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "trailing JSON",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":[]}{}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "NaN",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":[{"period":"day","cost":NaN}]}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "Infinity",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":[{"period":"day","cost":Infinity}]}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "unknown limit field",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":[{"period":"day","tokens":1,"secret":"x"}]}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "duplicate limit field",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":[{"period":"day","period":"week","tokens":1}]}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "limits not array",
			body: `{"schemaVersion":1,"expectedPolicyRevision":"r","models":["a/b"],"limits":{}}`,
			code: PolicyErrOutputInvalid,
		},
		{
			name: "schema unsupported",
			body: `{"schemaVersion":2,"expectedPolicyRevision":"r","models":["a/b"],"limits":[]}`,
			code: PolicyErrSchemaUnsupported,
		},
		{
			name: "too large",
			body: strings.Repeat(" ", MaxPolicyPayload+1),
			code: PolicyErrOutputTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePolicyApply(strings.NewReader(tt.body))
			if got := policyCode(t, err); got != tt.code {
				t.Fatalf("code %q, want %q; error %v", got, tt.code, err)
			}
		})
	}

	if _, err := DecodePolicyApply(nil); policyCode(t, err) != PolicyErrCommandFailed {
		t.Fatal(err)
	}
}

func TestDescribePolicyIsSecretFreeAndUsesRawPatterns(t *testing.T) {
	now := policyTestNow(t)
	key, secret := policyTestKey(t, now)

	d, err := DescribePolicy(key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != 1 || !d.OK || d.Key.ID != key.ID ||
		d.Key.Name != key.Name || d.Key.State != "disabled" || !d.Key.ReadOnly ||
		d.Models.Mode != "restricted" ||
		!slices.Equal(d.Models.Patterns, []string{"openai/gpt-5.2"}) ||
		len(d.Limits) != 2 || d.Limits[0].Period != "hours" ||
		d.Limits[0].CycleStartedAt == nil || d.Limits[1].Period != "month" ||
		!d.Accounts.Restricted || d.Accounts.Count != 2 || d.Accounts.Digest == nil ||
		!strings.HasPrefix(d.PolicyRevision, "sha256:") {
		t.Fatalf("describe %+v", d)
	}
	if d.Models.Patterns[0] == "acme/*" {
		t.Fatal("describe returned account-derived HeldModels instead of raw patterns")
	}

	b, err := MarshalPolicyDescribe(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secret, key.Masked, "acme/account-1", "acme/account-2"} {
		if forbidden != "" && bytes.Contains(b, []byte(forbidden)) {
			t.Fatalf("machine output contains %q: %s", forbidden, b)
		}
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "masked", "tokenHash", "deviceToken"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("machine output has field %q: %s", forbidden, b)
		}
	}
}

func TestApplyPolicyAtomicallyReplacesModelsAndLimits(t *testing.T) {
	now := policyTestNow(t)
	key, secret := policyTestKey(t, now)
	before, err := DescribePolicy(key.ID)
	if err != nil {
		t.Fatal(err)
	}

	after, err := ApplyPolicy(key.ID, PolicyApply{
		SchemaVersion:          PolicySchemaVersion,
		ExpectedPolicyRevision: before.PolicyRevision,
		Models:                 []string{"openai/gpt-5.2", "anthropic/*"},
		Limits: []PolicyLimitInput{
			{Period: "hours", Hours: 5, Tokens: 42},
			{Period: "days", Days: 3, Cost: 1.25},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.PolicyRevision == before.PolicyRevision ||
		!slices.Equal(after.Models.Patterns, []string{"openai/gpt-5.2", "anthropic/*"}) ||
		len(after.Limits) != 2 || after.Limits[0].Tokens != 42 ||
		after.Limits[1].Days != 3 || after.Limits[1].Cost != 1.25 {
		t.Fatalf("after apply %+v", after)
	}
	if after.Limits[0].CycleStartedAt == nil || before.Limits[0].CycleStartedAt == nil ||
		*after.Limits[0].CycleStartedAt != *before.Limits[0].CycleStartedAt {
		t.Fatalf("same window lost its cycle start: before %+v after %+v", before.Limits[0], after.Limits[0])
	}
	if after.Limits[1].CycleStartedAt == nil ||
		*after.Limits[1].CycleStartedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("new cycle did not start now: %+v", after.Limits[1])
	}

	keys, err := load()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	kept := keys[0]
	if kept.Secret != secret || !kept.Off || !kept.ReadOnly ||
		kept.Issuer != key.Issuer || !kept.Expires.Equal(key.Expires) ||
		!slices.Equal(kept.Accounts, key.Accounts) {
		t.Fatalf("policy touched fields outside models/limits: %+v", kept)
	}
	if len(kept.Limits()) != 2 {
		t.Fatalf("limits kept as %+v", kept.Limits())
	}

	cleared, err := ApplyPolicy(key.ID, PolicyApply{
		SchemaVersion:          PolicySchemaVersion,
		ExpectedPolicyRevision: after.PolicyRevision,
		Models:                 []string{"openai/gpt-5.2"},
		Limits:                 []PolicyLimitInput{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cleared.Limits) != 0 {
		t.Fatalf("empty limits did not clear: %+v", cleared.Limits)
	}
	keys, _ = load()
	if keys[0].Limit != nil || len(keys[0].More) != 0 {
		t.Fatalf("cleared limits persisted as %+v %+v", keys[0].Limit, keys[0].More)
	}
}

func TestApplyPolicyRejectsWithoutWriting(t *testing.T) {
	now := policyTestNow(t)
	key, _ := policyTestKey(t, now)
	before, err := DescribePolicy(key.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(Path())
	if err != nil {
		t.Fatal(err)
	}
	base := PolicyApply{
		SchemaVersion:          PolicySchemaVersion,
		ExpectedPolicyRevision: before.PolicyRevision,
		Models:                 []string{"openai/gpt-5.2"},
	}
	tests := []struct {
		name string
		in   PolicyApply
		code string
	}{
		{
			name: "empty models",
			in:   PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{}, Limits: []PolicyLimitInput{}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "bare wildcard",
			in:   PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"*"}, Limits: []PolicyLimitInput{}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "duplicate window",
			in: PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{
				{Period: "month", Tokens: 1},
				{Period: "month", Cost: 1},
			}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "too many windows",
			in: PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{
				{Period: "day", Tokens: 1},
				{Period: "week", Tokens: 1},
				{Period: "month", Tokens: 1},
				{Period: "days", Days: 2, Tokens: 1},
				{Period: "hours", Hours: 2, Tokens: 1},
				{Period: "days", Days: 3, Tokens: 1},
			}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "negative tokens",
			in: PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{
				{Period: "day", Tokens: -1},
			}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "NaN cost",
			in: PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{
				{Period: "day", Cost: math.NaN()},
			}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "bad period",
			in: PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{
				{Period: "fortnight", Tokens: 1},
			}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "empty period",
			in: PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{
				{Period: " ", Tokens: 1},
			}},
			code: PolicyErrOutputInvalid,
		},
		{
			name: "stale revision",
			in:   PolicyApply{SchemaVersion: 1, ExpectedPolicyRevision: "sha256:stale", Models: []string{"a/b"}, Limits: []PolicyLimitInput{}},
			code: PolicyErrPolicyConflict,
		},
		{
			name: "unsupported schema",
			in:   PolicyApply{SchemaVersion: 2, ExpectedPolicyRevision: before.PolicyRevision, Models: []string{"a/b"}, Limits: []PolicyLimitInput{}},
			code: PolicyErrSchemaUnsupported,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyPolicy(key.ID, tt.in)
			if got := policyCode(t, err); got != tt.code {
				t.Fatalf("code %q, want %q; error %v", got, tt.code, err)
			}
			got, err := os.ReadFile(Path())
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("rejected policy wrote the store: %v\nbefore: %s\nafter: %s", err, raw, got)
			}
		})
	}

	// A concurrent account-scope change invalidates the old revision too.
	keys, _ := load()
	keys[0].Accounts = []string{"acme/account-3"}
	if err := save(keys); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(Path())
	_, err = ApplyPolicy(key.ID, base)
	if got := policyCode(t, err); got != PolicyErrPolicyConflict {
		t.Fatalf("account change: code %q, want conflict; %v", got, err)
	}
	if got, _ := os.ReadFile(Path()); !bytes.Equal(got, raw) {
		t.Fatal("conflicting policy wrote the store")
	}
}

func TestPolicyErrorsForMissingAndCorruptStore(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := DescribePolicy("missing"); policyCode(t, err) != PolicyErrKeyNotFound {
		t.Fatal(err)
	}
	if _, err := ApplyPolicy("missing", PolicyApply{SchemaVersion: 1}); policyCode(t, err) != PolicyErrKeyNotFound {
		t.Fatal(err)
	}
	if err := os.MkdirAll(Path()+"/..", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DescribePolicy("missing"); policyCode(t, err) != PolicyErrStorageUnavailable {
		t.Fatal(err)
	}
}

func TestMarshalPolicyFailureIsStableAndSecretFree(t *testing.T) {
	err := policyError(PolicyErrPolicyConflict, "The gateway policy changed; read it again before applying", false)
	b, marshalErr := MarshalPolicyFailure(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var out PolicyFailure
	if e := json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	if out.SchemaVersion != 1 || out.OK || out.Error.Code != PolicyErrPolicyConflict ||
		out.Error.Retryable || out.Error.Message == "" {
		t.Fatalf("failure %+v", out)
	}
	if _, err := MarshalPolicyDescribe(PolicyDescribe{SchemaVersion: 1, OK: false}); policyCode(t, err) != PolicyErrOutputInvalid {
		t.Fatal(err)
	}
}
