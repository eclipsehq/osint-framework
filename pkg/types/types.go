package types

import (
	"encoding/json"
	"time"
)

type ModuleResult struct {
	Module    string                 `json:"module"`
	Target    string                 `json:"target"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Error     error                  `json:"-"`
}

func (m ModuleResult) MarshalJSON() ([]byte, error) {
	type Alias ModuleResult
	return json.Marshal(&struct {
		*Alias
		Error string `json:"error,omitempty"`
	}{
		Alias: (*Alias)(&m),
		Error: func() string {
			if m.Error != nil {
				return m.Error.Error()
			}
			return ""
		}(),
	})
}
