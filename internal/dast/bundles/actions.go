package bundles

import "time"

type ActionKind string

const (
	ActionNavigate    ActionKind = "navigate"
	ActionClick       ActionKind = "click"
	ActionWaitForLoad ActionKind = "wait_for_load"
	ActionCaptchaMark ActionKind = "captcha_mark"
)

type Action struct {
	Kind      ActionKind `json:"kind"`
	URL       string     `json:"url,omitempty"`
	Selector  string     `json:"selector,omitempty"`
	MinWaitMs int        `json:"min_wait_ms,omitempty"`
	MaxWaitMs int        `json:"max_wait_ms,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}
