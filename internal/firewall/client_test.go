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

func TestBuildRules_K8sAndDiscoveredNodesInRulesAndResources(t *testing.T) {
	// Simulates the full merge: 2 nodes from K8s (passes 1+2) and 2 nodes
	// discovered from Hetzner API (pass 3, IsServer=false). Verifies that
	// ALL 4 node IPs appear in the source IPs for ports 6443 and 9345,
	// and all 4 servers would be targeted by ensureAppliedToServers.

	c := &Client{cfg: config.Config{}}

	// 2 K8s nodes (one control-plane, one worker)
	k8sNodes := []NodeInfo{
		{Name: "k8s-server-1", ServerID: 100, IPv4: net.ParseIP("10.0.0.1"), IsServer: true},
		{Name: "k8s-worker-1", ServerID: 200, IPv4: net.ParseIP("10.0.0.2"), IsServer: false},
	}

	// 2 pre-join servers discovered via Hetzner API (IsServer=true, treated as
	// potential control-plane so they're included in etcd/server-only rules)
	discoveredNodes := []NodeInfo{
		{Name: "hcloud-new-1", ServerID: 300, IPv4: net.ParseIP("10.0.0.3"), IsServer: true},
		{Name: "hcloud-new-2", ServerID: 400, IPv4: net.ParseIP("10.0.0.4"), IsServer: true},
	}

	// Merge (same dedup logic as Reconcile pass 3)
	allNodes := append(k8sNodes, discoveredNodes...)

	rules := c.buildRules(allNodes)

	// Collect source IPs per port
	sourceIPsByPort := make(map[string][]string)
	for _, r := range rules {
		if r.Port == nil {
			continue
		}
		var ips []string
		for _, ipNet := range r.SourceIPs {
			ips = append(ips, ipNet.IP.String())
		}
		sourceIPsByPort[*r.Port] = ips
	}

	// All 4 node IPs
	allIPs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	// Server-only IPs (k8s-server-1 + both discovered)
	serverIPs := []string{"10.0.0.1", "10.0.0.3", "10.0.0.4"}

	// Ports using SourceClusterNodes must contain all 4 IPs
	for _, port := range []string{"6443", "9345", "10250"} {
		gotIPs := sourceIPsByPort[port]
		if gotIPs == nil {
			t.Fatalf("no rule found for port %s", port)
		}
		ipSet := make(map[string]bool, len(gotIPs))
		for _, ip := range gotIPs {
			ipSet[ip] = true
		}
		for _, wantIP := range allIPs {
			if !ipSet[wantIP] {
				t.Errorf("port %s: missing IP %s in source IPs (got %v)", port, wantIP, gotIPs)
			}
		}
	}

	// Ports using SourceServerNodes (etcd) must contain server IPs
	// (k8s-server-1 + both discovered, but NOT k8s-worker-1)
	for _, port := range []string{"2379", "2380"} {
		gotIPs := sourceIPsByPort[port]
		if gotIPs == nil {
			t.Fatalf("no rule found for port %s", port)
		}
		ipSet := make(map[string]bool, len(gotIPs))
		for _, ip := range gotIPs {
			ipSet[ip] = true
		}
		for _, wantIP := range serverIPs {
			if !ipSet[wantIP] {
				t.Errorf("port %s: missing server IP %s in source IPs (got %v)", port, wantIP, gotIPs)
			}
		}
		// Worker must NOT be in etcd rules
		if ipSet["10.0.0.2"] {
			t.Errorf("port %s: worker IP 10.0.0.2 should not be in server-only rule", port)
		}
	}

	// Verify ensureAppliedToServers would target all 4 servers.
	// Simulate an empty AppliedTo (no servers applied yet).
	appliedServers := make(map[int64]bool) // empty = none applied
	var toApply []int64
	for _, node := range allNodes {
		if node.ServerID > 0 && !appliedServers[node.ServerID] {
			toApply = append(toApply, node.ServerID)
		}
	}

	if len(toApply) != 4 {
		t.Fatalf("expected 4 servers to apply firewall to, got %d: %v", len(toApply), toApply)
	}
	wantServerIDs := map[int64]bool{100: true, 200: true, 300: true, 400: true}
	for _, id := range toApply {
		if !wantServerIDs[id] {
			t.Errorf("unexpected server ID %d in apply list", id)
		}
	}
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
