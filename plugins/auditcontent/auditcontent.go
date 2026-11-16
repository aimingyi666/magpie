// Package auditcontent sends captured conversation text to the enterprise
// control plane. It is off unless MAGPIE_AUDIT_CONTENT_ENABLED is explicitly
// true, and a configuration error fails only this plugin.
package auditcontent

import (
	"github.com/yetone/magpie/internal/auditcontent"
	"github.com/yetone/magpie/internal/pluginrt"
	"github.com/yetone/magpie/internal/usage"
)

func init() {
	pluginrt.Register(pluginrt.Manifest{
		ID:       "auditcontent",
		API:      "^1",
		Requires: []string{"window", "settings", "gateway"},
		Name:     "Audit content capture",
		Sub:      "Send prompt and reply text to the enterprise audit service",
		One:      "Capturing content",
		Many:     "Capturing content",
		InUse: func() (int, error) {
			config, err := auditcontent.FromEnv()
			if err != nil {
				return 0, err
			}
			if config.Enabled {
				return 1, nil
			}
			return 0, nil
		},
		Apply: func(c *pluginrt.Ctx) error {
			config, err := auditcontent.FromEnv()
			if err != nil {
				return err
			}
			if !config.Enabled {
				return nil
			}
			c.OnDispose(usage.Observe(auditcontent.New(config)))
			return nil
		},
	})
}
