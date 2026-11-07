package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// ManagedPolicy is what an enterprise distributed to this computer: rules
// added to the user's own, and whether the baseline categories (secrets and
// the personal data magpie always masks) may be turned off here at all.
//
// The file is written by the enterprise sync, not by Settings: a user can
// edit settings.json, and an enterprise's compliance does not depend on
// them not doing so.
type ManagedPolicy struct {
	SchemaVersion   int    `json:"schemaVersion"`
	RequireBaseline bool   `json:"requireBaseline"`
	Rules           []Rule `json:"rules"`
	Source          string `json:"source,omitempty"`
}

// ParseManagedPolicy reads a distributed policy, refusing anything it does
// not understand. A rule that cannot work refuses the whole file: half a
// policy is not a policy.
func ParseManagedPolicy(b []byte) (ManagedPolicy, error) {
	var p ManagedPolicy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return ManagedPolicy{}, fmt.Errorf("the managed masking policy is not valid JSON: %v", err)
	}
	if p.SchemaVersion != 1 {
		return ManagedPolicy{}, fmt.Errorf("the managed masking policy has schema version %d, not 1", p.SchemaVersion)
	}
	rules, err := CheckRules(p.Rules)
	if err != nil {
		return ManagedPolicy{}, err
	}
	p.Rules = rules
	return p, nil
}

// LoadManagedPolicy reads a policy file. A missing file is no policy, not
// an error.
func LoadManagedPolicy(path string) (ManagedPolicy, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ManagedPolicy{}, false, nil
		}
		return ManagedPolicy{}, false, err
	}
	p, err := ParseManagedPolicy(b)
	if err != nil {
		return ManagedPolicy{}, false, err
	}
	return p, true, nil
}
