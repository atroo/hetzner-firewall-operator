package firewall

import (
	"net"
	"testing"

	"github.com/atroo/hetzner-firewall-operator/internal/config"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func TestNodeIPNets(t *testing.T) {
	nodes := []NodeInfo{
		{
			Name:     "server-1",
			IPv4:     net.ParseIP("1.2.3.4"),
			IPv6Net:  &net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)},
			IsServer: true,
		},
		{
			Name:     "worker-1",
			IPv4:     net.ParseIP("5.6.7.8"),
			IsServer: false,
		},
	}

	t.Run("all nodes", func(t *testing.T) {
		nets := nodeIPNets(nodes, false)
		// server-1 IPv4 + server-1 IPv6 + worker-1 IPv4 = 3
		if len(nets) != 3 {
			t.Fatalf("expected 3 nets, got %d", len(nets))
		}
	})

	t.Run("server only", func(t *testing.T) {
		nets := nodeIPNets(nodes, true)
		// server-1 IPv4 + server-1 IPv6 = 2
		if len(nets) != 2 {
			t.Fatalf("expected 2 nets, got %d", len(nets))
		}
		// Verify it's a /32
		ones, bits := nets[0].Mask.Size()
		if ones != 32 || bits != 32 {
			t.Errorf("expected /32, got /%d (bits=%d)", ones, bits)
		}
	})

	t.Run("empty nodes", func(t *testing.T) {
		nets := nodeIPNets(nil, false)
		if len(nets) != 0 {
			t.Errorf("expected 0 nets, got %d", len(nets))
		}
	})

	t.Run("node with no IPs", func(t *testing.T) {
		noIP := []NodeInfo{{Name: "empty", IsServer: false}}
		nets := nodeIPNets(noIP, false)
		if len(nets) != 0 {
			t.Errorf("expected 0 nets, got %d", len(nets))
		}
	})
}

func TestParseSSHCIDRs(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
		want  int
	}{
		{
			name:  "valid CIDRs",
			cidrs: []string{"1.2.3.4/32", "10.0.0.0/8"},
			want:  2,
		},
		{
			name:  "mixed valid and invalid",
			cidrs: []string{"1.2.3.4/32", "not-a-cidr", "10.0.0.0/8"},
			want:  2,
		},
		{
			name:  "all invalid",
			cidrs: []string{"bad", "also-bad"},
			want:  0,
		},
		{
			name:  "empty slice",
			cidrs: nil,
			want:  0,
		},
		{
			name:  "IPv6 CIDR",
			cidrs: []string{"2001:db8::/32"},
			want:  1,
		},
		{
			name:  "bare IP without mask",
			cidrs: []string{"1.2.3.4"},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSHCIDRs(tt.cidrs)
			if len(got) != tt.want {
				t.Errorf("parseSSHCIDRs(%v) returned %d nets, want %d", tt.cidrs, len(got), tt.want)
			}
		})
	}
}

func TestRulesEqual(t *testing.T) {
	rule1 := hcloud.FirewallRule{
		Direction: hcloud.FirewallRuleDirectionIn,
		Protocol:  hcloud.FirewallRuleProtocolTCP,
		Port:      hcloud.Ptr("443"),
		SourceIPs: []net.IPNet{{IP: net.ParseIP("1.2.3.4").To4(), Mask: net.CIDRMask(32, 32)}},
	}
	rule2 := hcloud.FirewallRule{
		Direction: hcloud.FirewallRuleDirectionIn,
		Protocol:  hcloud.FirewallRuleProtocolTCP,
		Port:      hcloud.Ptr("80"),
		SourceIPs: []net.IPNet{{IP: net.ParseIP("5.6.7.8").To4(), Mask: net.CIDRMask(32, 32)}},
	}

	t.Run("equal same order", func(t *testing.T) {
		if !rulesEqual([]hcloud.FirewallRule{rule1, rule2}, []hcloud.FirewallRule{rule1, rule2}) {
			t.Error("expected equal")
		}
	})

	t.Run("equal different order", func(t *testing.T) {
		if !rulesEqual([]hcloud.FirewallRule{rule1, rule2}, []hcloud.FirewallRule{rule2, rule1}) {
			t.Error("expected equal (order independent)")
		}
	})

	t.Run("different length", func(t *testing.T) {
		if rulesEqual([]hcloud.FirewallRule{rule1}, []hcloud.FirewallRule{rule1, rule2}) {
			t.Error("expected not equal")
		}
	})

	t.Run("both empty", func(t *testing.T) {
		if !rulesEqual(nil, nil) {
			t.Error("expected equal")
		}
	})

	t.Run("different rules", func(t *testing.T) {
		rule3 := rule1
		rule3.Protocol = hcloud.FirewallRuleProtocolUDP
		if rulesEqual([]hcloud.FirewallRule{rule1}, []hcloud.FirewallRule{rule3}) {
			t.Error("expected not equal")
		}
	})
}

func TestBuildRules(t *testing.T) {
	c := &Client{
		cfg: config.Config{
			NodePortPublic: false,
		},
	}

	nodes := []NodeInfo{
		{
			Name:     "server-1",
			IPv4:     net.ParseIP("1.2.3.4"),
			IsServer: true,
		},
		{
			Name:     "worker-1",
			IPv4:     net.ParseIP("5.6.7.8"),
			IsServer: false,
		},
	}

	rules := c.buildRules(nodes)

	if len(rules) == 0 {
		t.Fatal("expected rules to be generated")
	}

	// Verify we have rules for key ports
	portFound := make(map[string]bool)
	for _, r := range rules {
		if r.Port != nil {
			portFound[*r.Port] = true
		}
	}

	expectedPorts := []string{"9345", "6443", "8472", "10250", "2379", "2380", "4240", "4245", "80", "443", "30000-32767"}
	for _, port := range expectedPorts {
		if !portFound[port] {
			t.Errorf("expected rule for port %s", port)
		}
	}

	// Verify etcd rules only have server node IPs
	for _, r := range rules {
		if r.Description != nil && *r.Description == "etcd client requests" {
			if len(r.SourceIPs) != 1 {
				t.Errorf("etcd rule should have 1 source IP (server only), got %d", len(r.SourceIPs))
			}
		}
	}
}

func TestBuildRulesWithSSH(t *testing.T) {
	c := &Client{
		cfg: config.Config{
			AllowSSHFrom: []string{"10.0.0.0/8", "192.168.1.0/24"},
		},
	}

	nodes := []NodeInfo{
		{Name: "server-1", IPv4: net.ParseIP("1.2.3.4"), IsServer: true},
	}

	rules := c.buildRules(nodes)

	var sshRule *hcloud.FirewallRule
	for i, r := range rules {
		if r.Description != nil && *r.Description == "SSH access" {
			sshRule = &rules[i]
			break
		}
	}

	if sshRule == nil {
		t.Fatal("expected SSH rule")
	}

	if len(sshRule.SourceIPs) != 2 {
		t.Errorf("SSH rule should have 2 source CIDRs, got %d", len(sshRule.SourceIPs))
	}
}

func TestBuildRulesNoSSH(t *testing.T) {
	c := &Client{
		cfg: config.Config{},
	}

	nodes := []NodeInfo{
		{Name: "server-1", IPv4: net.ParseIP("1.2.3.4"), IsServer: true},
	}

	rules := c.buildRules(nodes)

	for _, r := range rules {
		if r.Description != nil && *r.Description == "SSH access" {
			t.Error("SSH rule should not be present when AllowSSHFrom is empty")
		}
	}
}

func TestBuildRulesNodePortPublic(t *testing.T) {
	nodes := []NodeInfo{
		{Name: "server-1", IPv4: net.ParseIP("1.2.3.4"), IsServer: true},
	}

	t.Run("nodeport cluster only", func(t *testing.T) {
		c := &Client{cfg: config.Config{NodePortPublic: false}}
		rules := c.buildRules(nodes)
		for _, r := range rules {
			if r.Description != nil && *r.Description == "NodePort services (TCP)" {
				// Should have only node IPs, not 0.0.0.0/0
				for _, ip := range r.SourceIPs {
					if ip.String() == "0.0.0.0/0" {
						t.Error("NodePort should not be public")
					}
				}
			}
		}
	})

	t.Run("nodeport public", func(t *testing.T) {
		c := &Client{cfg: config.Config{NodePortPublic: true}}
		rules := c.buildRules(nodes)
		for _, r := range rules {
			if r.Description != nil && *r.Description == "NodePort services (TCP)" {
				hasPublic := false
				for _, ip := range r.SourceIPs {
					if ip.String() == "0.0.0.0/0" {
						hasPublic = true
					}
				}
				if !hasPublic {
					t.Error("NodePort should be public")
				}
			}
		}
	})
}

func TestBuildRulesEmptyNodes(t *testing.T) {
	c := &Client{cfg: config.Config{}}
	rules := c.buildRules(nil)

	// Public rules (HTTP, HTTPS) should still exist
	// Cluster-only rules should be skipped (no source IPs)
	for _, r := range rules {
		if r.Description != nil && *r.Description == "Cilium VXLAN overlay" {
			t.Error("cluster-only rules should be skipped when no nodes exist")
		}
	}
}
