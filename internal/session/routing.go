package session

// GatewaysForGroup respects explicit configuration overrides. ShanghaiTech also
// retains the old flattened-list fallback for incomplete controller responses.
func (c *Credential) GatewaysForGroup(group string) []string {
	var assigned []string
	if c.Policy != nil {
		if group == "" {
			assigned = c.Policy.Gateways
		} else {
			assigned = c.Policy.NodeGroups[group]
		}
	}
	if c.GatewayOverride {
		var matching []string
		for _, addr := range assigned {
			for _, allowed := range c.Gateways {
				if addr == allowed {
					matching = append(matching, addr)
					break
				}
			}
		}
		if len(matching) != 0 {
			return matching
		}
		return append([]string(nil), c.Gateways...)
	}
	if len(assigned) == 0 && (group == "" || c.LegacyRouting) {
		assigned = c.Gateways
	}
	return append([]string(nil), assigned...)
}

func (c *Credential) GatewayGroupForApp(appID string) string {
	if c.Policy == nil {
		return ""
	}
	if group := c.Policy.AppNodeGroups[appID]; group != "" {
		return group
	}
	return c.Policy.MajorNodeGroup
}

func (c *Credential) GatewaysForApp(appID string) []string {
	return c.GatewaysForGroup(c.GatewayGroupForApp(appID))
}
