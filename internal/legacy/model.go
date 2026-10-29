package legacy

import "encoding/json"

// The old library as the old App wrote it, schema version 3: only the
// fields an import reads. Lines and rule sets live in profiles; groups and
// scenarios are global and refer to them by id.

// Library is the whole old library.
type Library struct {
	SchemaVersion    int        `json:"schemaVersion"`
	Profiles         []Record   `json:"profiles"`
	Groups           []Line     `json:"groups"`
	Scenarios        []Scenario `json:"scenarios"`
	ActiveScenarioID string     `json:"activeScenarioID"`
}

// Record is one profile.
type Record struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Profile Profile `json:"profile"`
}

// Profile holds a profile's own lines and rule sets.
type Profile struct {
	Lines         []Line            `json:"lines"`
	RuleSets      []RuleSet         `json:"rule_sets"`
	Subscriptions []json.RawMessage `json:"subscriptions"`
	Tailscale     struct {
		Hostname string `json:"hostname"`
	} `json:"tailscale"`
}

// Line is a line or, with type selector or urltest, a group.
type Line struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Enabled  *bool  `json:"enabled"`
	UDP      bool   `json:"udp"`
	TFO      bool   `json:"tfo"`
	Insecure bool   `json:"allow_insecure"`

	GroupMembers  []string `json:"group_members"`
	GroupDefault  string   `json:"group_default"`
	GroupURL      string   `json:"group_url"`
	GroupInterval string   `json:"group_interval"`

	NativeOptions json.RawMessage `json:"native_options"`

	VPNServer   string `json:"vpn_server"`
	VPNUsername string `json:"vpn_username"`
	VPNPassword string `json:"vpn_password"`

	TrojanServer   string `json:"trojan_server"`
	TrojanPort     int    `json:"trojan_port"`
	TrojanPassword string `json:"trojan_password"`
	TrojanSNI      string `json:"trojan_sni"`

	SSServer   string `json:"ss_server"`
	SSPort     int    `json:"ss_port"`
	SSMethod   string `json:"ss_method"`
	SSPassword string `json:"ss_password"`

	VMessServer string `json:"vmess_server"`
	VMessPort   int    `json:"vmess_port"`
	VMessUUID   string `json:"vmess_uuid"`
	VMessAltID  int    `json:"vmess_alt_id"`

	AnyTLSServer            string   `json:"anytls_server"`
	AnyTLSPort              int      `json:"anytls_port"`
	AnyTLSPassword          string   `json:"anytls_password"`
	AnyTLSSNI               string   `json:"anytls_sni"`
	AnyTLSClientFingerprint string   `json:"anytls_client_fingerprint"`
	AnyTLSALPN              []string `json:"anytls_alpn"`
	AnyTLSIdleCheck         int      `json:"anytls_idle_session_check_interval"`
	AnyTLSIdleTimeout       int      `json:"anytls_idle_session_timeout"`
	AnyTLSMinIdle           int      `json:"anytls_min_idle_session"`

	TailscaleExitNode string `json:"tailscale_exit_node"`
	TailscaleMagicDNS bool   `json:"tailscale_magic_dns"`
}

func (l *Line) enabled() bool { return l.Enabled == nil || *l.Enabled }
func (l *Line) isGroup() bool { return l.Type == "selector" || l.Type == "urltest" }

// RuleSet is a rule set or, with type group, a set of conditions, each a
// rule set of its own kind.
type RuleSet struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Type         string          `json:"type"`
	Enabled      *bool           `json:"enabled"`
	URL          string          `json:"url"`
	Format       string          `json:"format"`
	FetchLineID  string          `json:"fetch_line_id"`
	Invert       bool            `json:"invert"`
	NoResolve    bool            `json:"no_resolve"`
	Domains      []string        `json:"domains"`
	CIDRs        []string        `json:"cidrs"`
	Applications []Application   `json:"applications"`
	Processes    []string        `json:"processes"`
	NativeRule   json.RawMessage `json:"native_rule"`
	Conditions   []RuleSet       `json:"conditions"`
}

func (r *RuleSet) enabled() bool { return r.Enabled == nil || *r.Enabled }

// Application is an app a rule matches by its bundle.
type Application struct {
	BundleIdentifier string `json:"bundle_identifier"`
	Name             string `json:"name"`
	Path             string `json:"path"`
}

// Scenario binds rule sets to lines, in an order of its own when it was
// imported with interleaved conditions.
type Scenario struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Bindings              []Binding `json:"bindings"`
	DefaultLineID         string    `json:"default_line_id"`
	DefaultSubscriptionID string    `json:"default_subscription_id"`
	MatchOrder            []string  `json:"match_order"`
	MatchSSIDs            []string  `json:"match_ssids"`
	Icon                  string    `json:"icon"`
}

// Binding sends a rule set, or some of its conditions, to a line.
type Binding struct {
	RuleSetID      string   `json:"rule_set_id"`
	LineID         string   `json:"line_id"`
	SubscriptionID string   `json:"subscription_id"`
	ConditionIDs   []string `json:"condition_ids"`
}
