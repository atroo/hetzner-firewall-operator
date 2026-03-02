package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/atroo/hetzner-firewall-operator/internal/config"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// NodeInfo holds the IP addresses of a Kubernetes node.
type NodeInfo struct {
	Name       string
	ServerID   int64
	IPv4       net.IP
	IPv6Net    *net.IPNet // /64 network assigned by Hetzner
	IsServer   bool       // true if control-plane node
}

// Client wraps the Hetzner Cloud API for firewall operations.
type Client struct {
	hcloud *hcloud.Client
	logger *slog.Logger
	cfg    config.Config
}

// NewClient creates a new Hetzner firewall client.
func NewClient(hcloudClient *hcloud.Client, cfg config.Config, logger *slog.Logger) *Client {
	return &Client{
		hcloud: hcloudClient,
		logger: logger,
		cfg:    cfg,
	}
}

// EnsureFirewall creates the managed firewall if it doesn't exist and returns it.
func (c *Client) EnsureFirewall(ctx context.Context) (*hcloud.Firewall, error) {
	fw, _, err := c.hcloud.Firewall.GetByName(ctx, c.cfg.FirewallName)
	if err != nil {
		return nil, fmt.Errorf("get firewall by name: %w", err)
	}
	if fw != nil {
		return fw, nil
	}

	c.logger.Info("creating firewall", "name", c.cfg.FirewallName)
	result, _, err := c.hcloud.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
		Name:   c.cfg.FirewallName,
		Labels: map[string]string{"managed-by": "hetzner-firewall-operator"},
	})
	if err != nil {
		return nil, fmt.Errorf("create firewall: %w", err)
	}
	return result.Firewall, nil
}

// Reconcile computes the desired firewall rules from the current set of nodes
// and applies them to the managed Hetzner firewall.
func (c *Client) Reconcile(ctx context.Context, nodes []NodeInfo) error {
	fw, err := c.EnsureFirewall(ctx)
	if err != nil {
		return err
	}

	desired := c.buildRules(nodes)

	if rulesEqual(fw.Rules, desired) {
		c.logger.Debug("firewall rules already up to date", "ruleCount", len(desired))
		return nil
	}

	c.logger.Info("updating firewall rules",
		"firewall", c.cfg.FirewallName,
		"ruleCount", len(desired),
		"nodeCount", len(nodes),
	)

	_, _, err = c.hcloud.Firewall.SetRules(ctx, fw, hcloud.FirewallSetRulesOpts{
		Rules: desired,
	})
	if err != nil {
		return fmt.Errorf("set firewall rules: %w", err)
	}

	// Ensure firewall is applied to all node servers
	if err := c.ensureAppliedToServers(ctx, fw, nodes); err != nil {
		return fmt.Errorf("apply firewall to servers: %w", err)
	}

	return nil
}

// buildRules generates the desired Hetzner firewall rules based on nodes and config.
func (c *Client) buildRules(nodes []NodeInfo) []hcloud.FirewallRule {
	allNodeNets := nodeIPNets(nodes, false)
	serverNodeNets := nodeIPNets(nodes, true)
	publicNets := config.PublicNetworks()

	portRules := config.RKE2CiliumRules(c.cfg.NodePortPublic)

	// Add SSH rules if configured
	if len(c.cfg.AllowSSHFrom) > 0 {
		sshNets := parseSSHCIDRs(c.cfg.AllowSSHFrom)
		portRules = append(portRules, config.PortRule{
			Description: "SSH access",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "22",
			SourceType:  config.SourcePublic, // We'll override with custom CIDRs
		})
		// We handle SSH specially below
		_ = sshNets
	}

	var rules []hcloud.FirewallRule
	for _, pr := range portRules {
		var sourceIPs []net.IPNet
		switch pr.SourceType {
		case config.SourceClusterNodes:
			sourceIPs = allNodeNets
		case config.SourceServerNodes:
			sourceIPs = serverNodeNets
		case config.SourcePublic:
			sourceIPs = publicNets
		}

		// Skip rules with no source IPs (e.g. no server nodes yet)
		if len(sourceIPs) == 0 {
			continue
		}

		rule := hcloud.FirewallRule{
			Direction:   pr.Direction,
			Protocol:    pr.Protocol,
			SourceIPs:   sourceIPs,
			Description: hcloud.Ptr(pr.Description),
		}
		if pr.Port != "" {
			rule.Port = hcloud.Ptr(pr.Port)
		}

		rules = append(rules, rule)
	}

	// Override SSH rule with custom CIDRs if configured
	if len(c.cfg.AllowSSHFrom) > 0 {
		sshNets := parseSSHCIDRs(c.cfg.AllowSSHFrom)
		if len(sshNets) > 0 {
			// Remove the SSH rule we added above and replace with custom CIDRs
			for i := len(rules) - 1; i >= 0; i-- {
				if rules[i].Description != nil && *rules[i].Description == "SSH access" {
					rules[i].SourceIPs = sshNets
					break
				}
			}
		}
	}

	return rules
}

// ensureAppliedToServers ensures the firewall is applied to all node servers.
func (c *Client) ensureAppliedToServers(ctx context.Context, fw *hcloud.Firewall, nodes []NodeInfo) error {
	// Build set of currently applied server IDs
	appliedServers := make(map[int64]bool)
	for _, res := range fw.AppliedTo {
		if res.Type == hcloud.FirewallResourceTypeServer && res.Server != nil {
			appliedServers[res.Server.ID] = true
		}
	}

	// Find servers not yet attached
	var toApply []hcloud.FirewallResource
	for _, node := range nodes {
		if node.ServerID > 0 && !appliedServers[node.ServerID] {
			toApply = append(toApply, hcloud.FirewallResource{
				Type:   hcloud.FirewallResourceTypeServer,
				Server: &hcloud.FirewallResourceServer{ID: node.ServerID},
			})
		}
	}

	if len(toApply) == 0 {
		return nil
	}

	c.logger.Info("applying firewall to new servers", "count", len(toApply))
	_, _, err := c.hcloud.Firewall.ApplyResources(ctx, fw, toApply)
	return err
}

// nodeIPNets converts node IPs to /32 (v4) and /128 or /64 (v6) networks.
func nodeIPNets(nodes []NodeInfo, serverOnly bool) []net.IPNet {
	var nets []net.IPNet
	for _, n := range nodes {
		if serverOnly && !n.IsServer {
			continue
		}
		if n.IPv4 != nil {
			nets = append(nets, net.IPNet{
				IP:   n.IPv4.To4(),
				Mask: net.CIDRMask(32, 32),
			})
		}
		if n.IPv6Net != nil {
			// Use the /64 network that Hetzner assigns
			nets = append(nets, *n.IPv6Net)
		}
	}
	return nets
}

// parseSSHCIDRs parses a list of CIDR strings for SSH allowlist.
func parseSSHCIDRs(cidrs []string) []net.IPNet {
	var nets []net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, *ipNet)
	}
	return nets
}

// rulesEqual compares two rule sets (order-independent).
func rulesEqual(a, b []hcloud.FirewallRule) bool {
	if len(a) != len(b) {
		return false
	}

	aStr := rulesToSortedStrings(a)
	bStr := rulesToSortedStrings(b)

	for i := range aStr {
		if aStr[i] != bStr[i] {
			return false
		}
	}
	return true
}

func rulesToSortedStrings(rules []hcloud.FirewallRule) []string {
	var strs []string
	for _, r := range rules {
		port := ""
		if r.Port != nil {
			port = *r.Port
		}
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}

		var ips []string
		for _, ip := range r.SourceIPs {
			ips = append(ips, ip.String())
		}
		sort.Strings(ips)

		s := fmt.Sprintf("%s|%s|%s|%s|%s",
			r.Direction, r.Protocol, port, desc, strings.Join(ips, ","))
		strs = append(strs, s)
	}
	sort.Strings(strs)
	return strs
}
