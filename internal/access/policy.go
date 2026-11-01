package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"
)

const (
	PolicySchemaVersion = 1
	MaxPolicyPayload    = 64 << 10
)

const (
	PolicyErrKeyNotFound        = "gateway_key_not_found"
	PolicyErrPolicyConflict     = "gateway_policy_conflict"
	PolicyErrSchemaUnsupported  = "gateway_schema_unsupported"
	PolicyErrOutputInvalid      = "gateway_output_invalid"
	PolicyErrOutputTooLarge     = "gateway_output_too_large"
	PolicyErrStorageUnavailable = "gateway_storage_unavailable"
	PolicyErrCommandFailed      = "gateway_command_failed"
	PolicyErrTimeout            = "gateway_timeout"
)

// PolicyError is an error a gateway-control adapter can map to its stable
// machine protocol without parsing a human-readable CLI message.
type PolicyError struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *PolicyError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func policyError(code, message string, retryable bool) error {
	return &PolicyError{Code: code, Message: message, Retryable: retryable}
}

// PolicyKey describes a key without carrying its credential or token hash.
type PolicyKey struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	State     string  `json:"state"`
	ReadOnly  bool    `json:"readOnly"`
	ExpiresAt *string `json:"expiresAt"`
}

type PolicyModels struct {
	Mode     string   `json:"mode"`
	Patterns []string `json:"patterns"`
}

type PolicyLimit struct {
	Period         string  `json:"period"`
	Days           int     `json:"days,omitempty"`
	Hours          int     `json:"hours,omitempty"`
	Tokens         int64   `json:"tokens,omitempty"`
	Cost           float64 `json:"cost,omitempty"`
	CacheReads     bool    `json:"cacheReads"`
	CycleStartedAt *string `json:"cycleStartedAt"`
}

type PolicyAccounts struct {
	Restricted bool    `json:"restricted"`
	Count      int     `json:"count"`
	Digest     *string `json:"digest"`
}

type PolicyDescribe struct {
	SchemaVersion  int            `json:"schemaVersion"`
	OK             bool           `json:"ok"`
	ObservedAt     string         `json:"observedAt"`
	Key            PolicyKey      `json:"key"`
	Models         PolicyModels   `json:"models"`
	Limits         []PolicyLimit  `json:"limits"`
	Accounts       PolicyAccounts `json:"accounts"`
	PolicyRevision string         `json:"policyRevision"`
}

type PolicyLimitInput struct {
	Period     string  `json:"period"`
	Days       int     `json:"days,omitempty"`
	Hours      int     `json:"hours,omitempty"`
	Tokens     int64   `json:"tokens,omitempty"`
	Cost       float64 `json:"cost,omitempty"`
	CacheReads bool    `json:"cacheReads,omitempty"`
}

// PolicyApply is the complete policy request accepted on stdin. Limits is
// allowed to be empty, which explicitly removes every limit.
type PolicyApply struct {
	SchemaVersion          int                `json:"schemaVersion"`
	ExpectedPolicyRevision string             `json:"expectedPolicyRevision"`
	Models                 []string           `json:"models"`
	Limits                 []PolicyLimitInput `json:"limits"`
}

type PolicyFailureError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type PolicyFailure struct {
	SchemaVersion int                `json:"schemaVersion"`
	OK            bool               `json:"ok"`
	Error         PolicyFailureError `json:"error"`
}

// DescribePolicy returns the machine-safe policy view of id. It holds the
// same cross-process file lock every key-store write uses.
func DescribePolicy(id string) (PolicyDescribe, error) {
	mu.Lock()
	defer mu.Unlock()

	keys, err := load()
	if err != nil {
		return PolicyDescribe{}, policyError(PolicyErrStorageUnavailable, "The gateway key store is unavailable", true)
	}
	i := slices.IndexFunc(keys, func(k Key) bool { return k.ID == id })
	if i < 0 {
		return PolicyDescribe{}, policyError(PolicyErrKeyNotFound, "The gateway key does not exist", false)
	}
	return describePolicy(keys[i], Now().Round(0)), nil
}

// ApplyPolicy atomically replaces the target key's models and limits. The
// revision check, validation, write and independent readback all happen
// while the key store's lock is held.
func ApplyPolicy(id string, in PolicyApply) (PolicyDescribe, error) {
	if in.SchemaVersion != PolicySchemaVersion {
		return PolicyDescribe{}, policyError(PolicyErrSchemaUnsupported, "This Magpie does not support that gateway policy schema", false)
	}

	mu.Lock()
	defer mu.Unlock()

	keys, err := load()
	if err != nil {
		return PolicyDescribe{}, policyError(PolicyErrStorageUnavailable, "The gateway key store is unavailable", true)
	}
	i := slices.IndexFunc(keys, func(k Key) bool { return k.ID == id })
	if i < 0 {
		return PolicyDescribe{}, policyError(PolicyErrKeyNotFound, "The gateway key does not exist", false)
	}

	now := Now().Round(0)
	current := describePolicy(keys[i], now)
	if in.ExpectedPolicyRevision == "" || in.ExpectedPolicyRevision != current.PolicyRevision {
		return PolicyDescribe{}, policyError(PolicyErrPolicyConflict, "The gateway policy changed; read it again before applying", false)
	}

	models, err := CleanModels(in.Models)
	if err != nil {
		return PolicyDescribe{}, policyError(PolicyErrOutputInvalid, err.Error(), false)
	}
	if len(models) == 0 {
		return PolicyDescribe{}, policyError(PolicyErrOutputInvalid, "A gateway policy must name at least one model", false)
	}
	limits, err := policyLimits(keys[i].Limits(), in.Limits, now)
	if err != nil {
		return PolicyDescribe{}, err
	}

	next := keys[i]
	next.Models = models
	next.setLimits(limits)
	target := describePolicy(next, now)
	if _, err := MarshalPolicyDescribe(target); err != nil {
		return PolicyDescribe{}, err
	}

	keys[i] = next
	if err := save(keys); err != nil {
		return PolicyDescribe{}, policyError(PolicyErrStorageUnavailable, "The gateway key store could not be updated", true)
	}

	readback, err := load()
	if err != nil {
		return PolicyDescribe{}, policyError(PolicyErrStorageUnavailable, "The saved gateway policy could not be read back", true)
	}
	j := slices.IndexFunc(readback, func(k Key) bool { return k.ID == id })
	if j < 0 {
		return PolicyDescribe{}, policyError(PolicyErrStorageUnavailable, "The saved gateway key could not be read back", true)
	}
	got := describePolicy(readback[j], now)
	if !samePolicyObservation(target, got) {
		return PolicyDescribe{}, policyError(PolicyErrStorageUnavailable, "The saved gateway policy did not match the requested policy", true)
	}
	return got, nil
}

func policyLimits(prev []*Limit, in []PolicyLimitInput, now time.Time) ([]Limit, error) {
	if len(in) > MaxLimits {
		return nil, policyError(PolicyErrOutputInvalid, fmt.Sprintf("A gateway policy can have at most %d limits", MaxLimits), false)
	}
	out := make([]Limit, 0, len(in))
	for _, raw := range in {
		if strings.TrimSpace(raw.Period) == "" {
			return nil, policyError(PolicyErrOutputInvalid, "Every gateway policy limit must name a period", false)
		}
		lim := Limit{
			Period:     raw.Period,
			Days:       raw.Days,
			Hours:      raw.Hours,
			Tokens:     raw.Tokens,
			Cost:       raw.Cost,
			CacheReads: raw.CacheReads,
		}
		valid, err := lim.Valid()
		if err != nil {
			return nil, policyError(PolicyErrOutputInvalid, err.Error(), false)
		}
		if valid == nil {
			return nil, policyError(PolicyErrOutputInvalid, "Every gateway policy limit must cap tokens, cost or both", false)
		}
		var previous *Limit
		for _, old := range prev {
			if old != nil && valid.sameWindow(old) {
				previous = old
				break
			}
		}
		valid.Since = sinceOf(previous, valid, now)
		for a := range out {
			if out[a].sameWindow(valid) {
				return nil, policyError(PolicyErrOutputInvalid, "A gateway policy cannot repeat the same limit window", false)
			}
		}
		out = append(out, *valid)
	}
	return out, nil
}

func describePolicy(k Key, now time.Time) PolicyDescribe {
	state := "enabled"
	switch {
	case k.Off:
		state = "disabled"
	case !k.Expires.IsZero() && !now.Before(k.Expires):
		state = "expired"
	}

	mode := "all"
	switch {
	case len(k.Models) > 0:
		mode = "restricted"
	case len(k.Accounts) > 0:
		mode = "accounts_only"
	}

	patterns := slices.Clone(k.Models)
	if patterns == nil {
		patterns = []string{}
	}
	limits := make([]PolicyLimit, 0, MaxLimits)
	for _, l := range k.Limits() {
		if l == nil {
			continue
		}
		limits = append(limits, PolicyLimit{
			Period:         l.Period,
			Days:           l.Days,
			Hours:          l.Hours,
			Tokens:         l.Tokens,
			Cost:           l.Cost,
			CacheReads:     l.CacheReads,
			CycleStartedAt: policyTime(l.Since),
		})
	}

	accounts := PolicyAccounts{
		Restricted: len(k.Accounts) > 0,
		Count:      len(k.Accounts),
		Digest:     accountDigest(k.Accounts),
	}
	key := PolicyKey{
		ID:        k.ID,
		Name:      k.Name,
		State:     state,
		ReadOnly:  k.ReadOnly,
		ExpiresAt: policyTime(k.Expires),
	}
	models := PolicyModels{Mode: mode, Patterns: patterns}
	out := PolicyDescribe{
		SchemaVersion: PolicySchemaVersion,
		OK:            true,
		ObservedAt:    now.UTC().Format(time.RFC3339Nano),
		Key:           key,
		Models:        models,
		Limits:        limits,
		Accounts:      accounts,
	}
	out.PolicyRevision = policyRevision(out)
	return out
}

func policyTime(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func accountDigest(accounts []string) *string {
	if len(accounts) == 0 {
		return nil
	}
	a := slices.Clone(accounts)
	slices.Sort(a)
	sum := sha256.Sum256([]byte(strings.Join(a, "\x00")))
	s := "sha256:" + hex.EncodeToString(sum[:])
	return &s
}

func policyRevision(d PolicyDescribe) string {
	type revisionLimit struct {
		Period     string  `json:"period"`
		Days       int     `json:"days"`
		Hours      int     `json:"hours"`
		Tokens     int64   `json:"tokens"`
		Cost       float64 `json:"cost"`
		CacheReads bool    `json:"cacheReads"`
	}
	type revisionModels struct {
		Mode     string   `json:"mode"`
		Patterns []string `json:"patterns"`
	}
	type revisionAccounts struct {
		Digest *string `json:"digest"`
	}
	type revision struct {
		State    string           `json:"state"`
		ReadOnly bool             `json:"readOnly"`
		Models   revisionModels   `json:"models"`
		Limits   []revisionLimit  `json:"limits"`
		Accounts revisionAccounts `json:"accounts"`
	}

	v := revision{
		State:    d.Key.State,
		ReadOnly: d.Key.ReadOnly,
		Models: revisionModels{
			Mode:     d.Models.Mode,
			Patterns: slices.Clone(d.Models.Patterns),
		},
		Limits:   make([]revisionLimit, 0, len(d.Limits)),
		Accounts: revisionAccounts{Digest: d.Accounts.Digest},
	}
	for _, l := range d.Limits {
		v.Limits = append(v.Limits, revisionLimit{
			Period:     l.Period,
			Days:       l.Days,
			Hours:      l.Hours,
			Tokens:     l.Tokens,
			Cost:       l.Cost,
			CacheReads: l.CacheReads,
		})
	}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func samePolicyObservation(a, b PolicyDescribe) bool {
	return a.PolicyRevision == b.PolicyRevision &&
		reflect.DeepEqual(a.Key, b.Key) &&
		reflect.DeepEqual(a.Models, b.Models) &&
		reflect.DeepEqual(a.Limits, b.Limits) &&
		reflect.DeepEqual(a.Accounts, b.Accounts)
}

// DecodePolicyApply reads one schema-v1 request. It rejects duplicate or
// unknown fields, trailing JSON, NaN/Inf and inputs larger than 64 KiB.
func DecodePolicyApply(r io.Reader) (PolicyApply, error) {
	var in PolicyApply
	if r == nil {
		return in, policyError(PolicyErrCommandFailed, "No gateway policy input was provided", false)
	}
	b, err := io.ReadAll(io.LimitReader(r, MaxPolicyPayload+1))
	if err != nil {
		return in, policyError(PolicyErrCommandFailed, "The gateway policy input could not be read", true)
	}
	if len(b) > MaxPolicyPayload {
		return in, policyError(PolicyErrOutputTooLarge, "The gateway policy input is larger than 64 KiB", false)
	}
	if err := validatePolicyJSON(b); err != nil {
		return in, policyError(PolicyErrOutputInvalid, "The gateway policy input is not valid schema-v1 JSON", false)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return PolicyApply{}, policyError(PolicyErrOutputInvalid, "The gateway policy input is not valid schema-v1 JSON", false)
	}
	if err := requireJSONEOF(dec); err != nil {
		return PolicyApply{}, policyError(PolicyErrOutputInvalid, "The gateway policy input has trailing JSON", false)
	}
	if in.SchemaVersion != PolicySchemaVersion {
		return PolicyApply{}, policyError(PolicyErrSchemaUnsupported, "This Magpie does not support that gateway policy schema", false)
	}
	return in, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func validatePolicyJSON(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("empty JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return errors.New("policy must be a JSON object")
	}
	if err := validatePolicyObject(dec); err != nil {
		return err
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return errors.New("unterminated policy object")
	}
	if tok, err = dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func validatePolicyObject(dec *json.Decoder) error {
	seen := map[string]bool{}
	required := map[string]bool{
		"schemaVersion":          false,
		"expectedPolicyRevision": false,
		"models":                 false,
		"limits":                 false,
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return errors.New("duplicate or invalid policy field")
		}
		seen[key] = true
		if _, ok := required[key]; !ok {
			return errors.New("unknown policy field")
		}
		required[key] = true
		if key == "limits" {
			if err := validatePolicyLimits(dec); err != nil {
				return err
			}
			continue
		}
		if err := consumeJSONValue(dec); err != nil {
			return err
		}
	}
	for key, found := range required {
		if !found {
			return fmt.Errorf("missing policy field %s", key)
		}
	}
	return nil
}

func validatePolicyLimits(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('[') {
		return errors.New("limits must be an array")
	}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return err
		}
		if tok != json.Delim('{') {
			return errors.New("each limit must be an object")
		}
		seen := map[string]bool{}
		allowed := map[string]bool{
			"period": true, "days": true, "hours": true,
			"tokens": true, "cost": true, "cacheReads": true,
		}
		for dec.More() {
			tok, err = dec.Token()
			if err != nil {
				return err
			}
			key, ok := tok.(string)
			if !ok || seen[key] || !allowed[key] {
				return errors.New("duplicate or unknown limit field")
			}
			seen[key] = true
			if err := consumeJSONValue(dec); err != nil {
				return err
			}
		}
		if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
			return errors.New("unterminated limit object")
		}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim(']') {
		return errors.New("unterminated limits array")
	}
	return nil
}

func consumeJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				tok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := tok.(string)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid JSON field")
				}
				seen[key] = true
				if err := consumeJSONValue(dec); err != nil {
					return err
				}
			}
			close, err := dec.Token()
			if err != nil || close != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for dec.More() {
				if err := consumeJSONValue(dec); err != nil {
					return err
				}
			}
			close, err := dec.Token()
			if err != nil || close != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		f, err := d.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return errors.New("invalid JSON number")
		}
	case float64:
		if math.IsNaN(d) || math.IsInf(d, 0) {
			return errors.New("invalid JSON number")
		}
	case nil, bool, string:
	default:
		return errors.New("unexpected JSON value")
	}
	return nil
}

// MarshalPolicyDescribe returns one compact schema-v1 JSON object without
// its trailing newline. The CLI adds exactly one newline.
func MarshalPolicyDescribe(d PolicyDescribe) ([]byte, error) {
	if d.SchemaVersion != PolicySchemaVersion || !d.OK {
		return nil, policyError(PolicyErrOutputInvalid, "Magpie produced an invalid gateway policy response", false)
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, policyError(PolicyErrOutputInvalid, "Magpie could not encode the gateway policy response", false)
	}
	if len(b)+1 > MaxPolicyPayload {
		return nil, policyError(PolicyErrOutputTooLarge, "The gateway policy response is larger than 64 KiB", false)
	}
	return b, nil
}

func PolicyFailureFromError(err error) PolicyFailure {
	var pe *PolicyError
	if errors.As(err, &pe) {
		message := pe.Message
		if message == "" {
			message = "The gateway command failed"
		}
		return PolicyFailure{
			SchemaVersion: PolicySchemaVersion,
			OK:            false,
			Error: PolicyFailureError{
				Code:      pe.Code,
				Message:   message,
				Retryable: pe.Retryable,
			},
		}
	}
	return PolicyFailure{
		SchemaVersion: PolicySchemaVersion,
		OK:            false,
		Error: PolicyFailureError{
			Code:      PolicyErrCommandFailed,
			Message:   "Magpie could not complete the gateway command",
			Retryable: false,
		},
	}
}

func MarshalPolicyFailure(err error) ([]byte, error) {
	b, marshalErr := json.Marshal(PolicyFailureFromError(err))
	if marshalErr != nil {
		return nil, policyError(PolicyErrOutputInvalid, "Magpie could not encode the gateway error response", false)
	}
	return b, nil
}
