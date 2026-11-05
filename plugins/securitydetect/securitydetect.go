// Package securitydetect sends metadata-only gateway detection events to an
// enterprise security service. It is off unless MAGPIE_SECURITY_DETECTION_ENABLED
// is explicitly true, and a configuration error fails only this plugin.
package securitydetect

import (
	"github.com/yetone/magpie/internal/pluginrt"
	"github.com/yetone/magpie/internal/securitydetect"
	"github.com/yetone/magpie/internal/usage"
)

func init() {
	pluginrt.Register(pluginrt.Manifest{
		ID:       "securitydetect",
		API:      "^1",
		Requires: []string{"window", "settings", "gateway"},
		Name:     "Security detection",
		Sub:      "Send metadata-only detection events to an enterprise security service",
		One:      "Sending detection events",
		Many:     "Sending detection events",
		InUse: func() (int, error) {
			config, err := securitydetect.FromEnv()
			if err != nil {
				return 0, err
			}
			if config.Enabled {
				return 1, nil
			}
			return 0, nil
		},
		Apply: func(c *pluginrt.Ctx) error {
			config, err := securitydetect.FromEnv()
			if err != nil {
				return err
			}
			if !config.Enabled {
				return nil
			}
			c.OnDispose(usage.Observe(securitydetect.New(config)))
			return nil
		},
	})
}
