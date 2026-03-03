package config

import (
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func TestRKE2CiliumRules(t *testing.T) {
	t.Run("default rules", func(t *testing.T) {
		rules := RKE2CiliumRules(false)

		if len(rules) == 0 {
			t.Fatal("expected rules")
		}

		// Verify key ports are present
		portMap := make(map[string]PortRule)
		for _, r := range rules {
			if r.Port != "" {
				portMap[r.Port] = r
			}
		}

		expectedPorts := map[string]struct {
			protocol   hcloud.FirewallRuleProtocol
			sourceType SourceType
		}{
			"9345":  {hcloud.FirewallRuleProtocolTCP, SourceClusterNodes},
			"6443":  {hcloud.FirewallRuleProtocolTCP, SourceClusterNodes},
			"8472":  {hcloud.FirewallRuleProtocolUDP, SourceClusterNodes},
			"10250": {hcloud.FirewallRuleProtocolTCP, SourceClusterNodes},
			"2379":  {hcloud.FirewallRuleProtocolTCP, SourceServerNodes},
			"2380":  {hcloud.FirewallRuleProtocolTCP, SourceServerNodes},
			"4240":  {hcloud.FirewallRuleProtocolTCP, SourceClusterNodes},
			"4245":  {hcloud.FirewallRuleProtocolTCP, SourceClusterNodes},
			"80":    {hcloud.FirewallRuleProtocolTCP, SourcePublic},
			"443":   {hcloud.FirewallRuleProtocolTCP, SourcePublic},
		}

		for port, expected := range expectedPorts {
			rule, ok := portMap[port]
			if !ok {
				t.Errorf("missing rule for port %s", port)
				continue
			}
			if rule.Protocol != expected.protocol {
				t.Errorf("port %s: expected protocol %s, got %s", port, expected.protocol, rule.Protocol)
			}
			if rule.SourceType != expected.sourceType {
				t.Errorf("port %s: expected source type %d, got %d", port, expected.sourceType, rule.SourceType)
			}
		}
	})

	t.Run("nodeport cluster only", func(t *testing.T) {
		rules := RKE2CiliumRules(false)
		for _, r := range rules {
			if r.Port == "30000-32767" && r.SourceType != SourceClusterNodes {
				t.Errorf("NodePort should be cluster-only when nodePortPublic=false, got source type %d", r.SourceType)
			}
		}
	})

	t.Run("nodeport public", func(t *testing.T) {
		rules := RKE2CiliumRules(true)
		for _, r := range rules {
			if r.Port == "30000-32767" && r.SourceType != SourcePublic {
				t.Errorf("NodePort should be public when nodePortPublic=true, got source type %d", r.SourceType)
			}
		}
	})

	t.Run("all rules are inbound", func(t *testing.T) {
		rules := RKE2CiliumRules(false)
		for _, r := range rules {
			if r.Direction != hcloud.FirewallRuleDirectionIn {
				t.Errorf("rule %q should be inbound", r.Description)
			}
		}
	})

	t.Run("has ICMP rule", func(t *testing.T) {
		rules := RKE2CiliumRules(false)
		hasICMP := false
		for _, r := range rules {
			if r.Protocol == hcloud.FirewallRuleProtocolICMP {
				hasICMP = true
				if r.Port != "" {
					t.Error("ICMP rule should not have a port")
				}
			}
		}
		if !hasICMP {
			t.Error("expected ICMP rule")
		}
	})
}

func TestPublicNetworks(t *testing.T) {
	nets := PublicNetworks()

	if len(nets) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(nets))
	}

	// Check IPv4 0.0.0.0/0
	if nets[0].String() != "0.0.0.0/0" {
		t.Errorf("expected 0.0.0.0/0, got %s", nets[0].String())
	}

	// Check IPv6 ::/0
	if nets[1].String() != "::/0" {
		t.Errorf("expected ::/0, got %s", nets[1].String())
	}
}
