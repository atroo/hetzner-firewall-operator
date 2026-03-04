package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atroo/hetzner-firewall-operator/internal/config"
	"github.com/atroo/hetzner-firewall-operator/internal/firewall"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// NodeReconciler watches Kubernetes nodes and reconciles Hetzner firewall rules.
type NodeReconciler struct {
	client.Client
	fwClient       *firewall.Client
	serverResolver firewall.ServerResolver
	cfg            config.Config
	logger         *slog.Logger

	// lastReconcile tracks the last successful reconciliation time
	// to implement rate limiting.
	lastReconcile time.Time

	// discoveryCh is used by the discovery poller to trigger reconciliation
	// when the set of discovered servers changes.
	discoveryCh chan event.GenericEvent

	// discoveredMu protects discoveredServers.
	discoveredMu sync.RWMutex
	// discoveredServers caches the latest results from DiscoverServers polling.
	discoveredServers []firewall.NodeInfo
}

// NewNodeReconciler creates a new NodeReconciler.
func NewNodeReconciler(
	k8sClient client.Client,
	fwClient *firewall.Client,
	serverResolver firewall.ServerResolver,
	cfg config.Config,
	logger *slog.Logger,
) *NodeReconciler {
	return &NodeReconciler{
		Client:         k8sClient,
		fwClient:       fwClient,
		serverResolver: serverResolver,
		cfg:            cfg,
		logger:         logger,
		discoveryCh:    make(chan event.GenericEvent, 1),
	}
}

// Reconcile is called when a Node changes. It collects all nodes and reconciles
// the Hetzner firewall rules.
func (r *NodeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Info("reconciling firewall rules", "trigger", req.NamespacedName.Name)

	// Rate limit: don't reconcile more often than every 10 seconds
	if time.Since(r.lastReconcile) < 10*time.Second {
		r.logger.Debug("skipping reconciliation (rate limited)")
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// List all nodes
	var nodeList corev1.NodeList
	listOpts := []client.ListOption{}
	if r.cfg.LabelSelector != "" {
		// If label selector is set, we still list all nodes for firewall rules
		// but only use the selector for filtering if needed
	}

	if err := r.List(ctx, &nodeList, listOpts...); err != nil {
		r.logger.Error("failed to list nodes", "error", err)
		return reconcile.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Convert K8s nodes to NodeInfo (passes 1+2: hcloud:// and RKE2 name resolution)
	nodes, err := r.extractNodeInfos(ctx, nodeList.Items)
	if err != nil {
		r.logger.Error("failed to extract node info", "error", err)
		return reconcile.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Pass 3: merge cached discovered servers (populated by discovery poller)
	if r.cfg.ServerNamePattern != "" {
		discovered := r.getDiscoveredServers()
		if len(discovered) > 0 {
			existing := make(map[int64]struct{}, len(nodes))
			for _, n := range nodes {
				if n.ServerID > 0 {
					existing[n.ServerID] = struct{}{}
				}
			}
			var added int
			for _, d := range discovered {
				if _, ok := existing[d.ServerID]; !ok {
					nodes = append(nodes, d)
					added++
				}
			}
			if added > 0 {
				r.logger.Info("added pre-join servers from discovery cache",
					"pattern", r.cfg.ServerNamePattern,
					"cached", len(discovered),
					"newServers", added,
				)
			}
		}
	}

	if len(nodes) == 0 {
		r.logger.Warn("no nodes found with valid Hetzner provider IDs")
		return reconcile.Result{RequeueAfter: r.cfg.ReconcileInterval}, nil
	}

	r.logger.Info("found cluster nodes",
		"total", len(nodeList.Items),
		"hetznerNodes", len(nodes),
		"serverNodes", countServerNodes(nodes),
	)

	// Reconcile firewall
	if err := r.fwClient.Reconcile(ctx, nodes); err != nil {
		r.logger.Error("failed to reconcile firewall", "error", err)
		return reconcile.Result{RequeueAfter: 30 * time.Second}, err
	}

	r.lastReconcile = time.Now()

	// Schedule next periodic reconciliation
	return reconcile.Result{RequeueAfter: r.cfg.ReconcileInterval}, nil
}

// extractNodeInfos converts K8s Node objects to firewall.NodeInfo using a two-pass approach:
// Pass 1 parses hcloud:// provider IDs (existing behavior).
// Pass 2 batch-resolves remaining nodes via the Hetzner API (for RKE2 without HCCM).
func (r *NodeReconciler) extractNodeInfos(ctx context.Context, nodes []corev1.Node) ([]firewall.NodeInfo, error) {
	var infos []firewall.NodeInfo
	var unresolvedNodes []corev1.Node

	// Pass 1: parse hcloud:// provider IDs
	for _, node := range nodes {
		serverID, err := parseHetznerProviderID(node.Spec.ProviderID)
		if err != nil {
			unresolvedNodes = append(unresolvedNodes, node)
			continue
		}

		if info, ok := r.buildNodeInfo(&node, serverID); ok {
			infos = append(infos, info)
		}
	}

	// Pass 2: batch-resolve remaining nodes via server resolver
	if len(unresolvedNodes) > 0 && r.serverResolver != nil {
		names := make([]string, len(unresolvedNodes))
		for i, n := range unresolvedNodes {
			names[i] = n.Name
		}

		resolved, err := r.serverResolver.ResolveServerIDs(ctx, names)
		if err != nil {
			r.logger.Warn("failed to resolve server IDs via Hetzner API, skipping unresolved nodes",
				"error", err,
				"nodeCount", len(unresolvedNodes),
			)
		} else {
			for i := range unresolvedNodes {
				node := &unresolvedNodes[i]
				serverID, ok := resolved[node.Name]
				if !ok {
					r.logger.Warn("could not resolve Hetzner server ID for node",
						"node", node.Name,
						"providerID", node.Spec.ProviderID,
					)
					continue
				}

				if info, ok := r.buildNodeInfo(node, serverID); ok {
					infos = append(infos, info)
				}
			}
		}
	} else if len(unresolvedNodes) > 0 {
		for _, node := range unresolvedNodes {
			r.logger.Debug("skipping node without Hetzner provider ID (no server resolver configured)",
				"node", node.Name,
				"providerID", node.Spec.ProviderID,
			)
		}
	}

	return infos, nil
}

// buildNodeInfo extracts IP addresses from a K8s node and builds a NodeInfo.
// Returns false if the node has no usable IP addresses.
func (r *NodeReconciler) buildNodeInfo(node *corev1.Node, serverID int64) (firewall.NodeInfo, bool) {
	info := firewall.NodeInfo{
		Name:     node.Name,
		ServerID: serverID,
		IsServer: isControlPlaneNode(node),
	}

	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeExternalIP || addr.Type == corev1.NodeInternalIP {
			ip := net.ParseIP(addr.Address)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				info.IPv4 = ip
			} else {
				mask := net.CIDRMask(64, 128)
				info.IPv6Net = &net.IPNet{
					IP:   ip.Mask(mask),
					Mask: mask,
				}
			}
		}
	}

	if info.IPv4 != nil || info.IPv6Net != nil {
		return info, true
	}
	r.logger.Warn("node has no usable IP addresses", "node", node.Name)
	return info, false
}

// Start implements manager.Runnable. It runs a discovery polling loop that
// checks the Hetzner API for new servers matching ServerNamePattern and
// triggers reconciliation when the set changes.
func (r *NodeReconciler) Start(ctx context.Context) error {
	if r.cfg.ServerNamePattern == "" {
		r.logger.Info("discovery poller disabled (no server name pattern)")
		return nil
	}

	interval := r.cfg.DiscoveryInterval
	if interval == 0 {
		interval = 30 * time.Second
	}

	r.logger.Info("starting discovery poller",
		"pattern", r.cfg.ServerNamePattern,
		"interval", interval,
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("discovery poller stopped")
			return nil
		case <-ticker.C:
			r.pollDiscovery(ctx)
		}
	}
}

// pollDiscovery calls DiscoverServers and triggers reconciliation if the set changed.
func (r *NodeReconciler) pollDiscovery(ctx context.Context) {
	discovered, err := r.serverResolver.DiscoverServers(ctx, r.cfg.ServerNamePattern)
	if err != nil {
		r.logger.Warn("discovery poll failed", "error", err)
		return
	}

	// Build sorted ID set for comparison
	newIDs := make([]int64, len(discovered))
	for i, d := range discovered {
		newIDs[i] = d.ServerID
	}
	sort.Slice(newIDs, func(i, j int) bool { return newIDs[i] < newIDs[j] })

	r.discoveredMu.RLock()
	oldIDs := make([]int64, len(r.discoveredServers))
	for i, d := range r.discoveredServers {
		oldIDs[i] = d.ServerID
	}
	r.discoveredMu.RUnlock()
	sort.Slice(oldIDs, func(i, j int) bool { return oldIDs[i] < oldIDs[j] })

	changed := !int64SliceEqual(newIDs, oldIDs)

	// Always update the cache
	r.discoveredMu.Lock()
	r.discoveredServers = discovered
	r.discoveredMu.Unlock()

	if changed {
		r.logger.Info("discovered server set changed, triggering reconciliation",
			"oldCount", len(oldIDs),
			"newCount", len(newIDs),
		)
		// Non-blocking send — if a reconcile is already pending, skip
		select {
		case r.discoveryCh <- event.GenericEvent{Object: &corev1.Node{}}:
		default:
		}
	}
}

// getDiscoveredServers returns a copy of the cached discovered servers.
func (r *NodeReconciler) getDiscoveredServers() []firewall.NodeInfo {
	r.discoveredMu.RLock()
	defer r.discoveredMu.RUnlock()
	if r.discoveredServers == nil {
		return nil
	}
	out := make([]firewall.NodeInfo, len(r.discoveredServers))
	copy(out, r.discoveredServers)
	return out
}

// int64SliceEqual returns true if two sorted int64 slices are equal.
func int64SliceEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SetupWithManager registers the controller with the manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		WatchesRawSource(source.Channel(r.discoveryCh, &handler.EnqueueRequestForObject{})).
		WithEventFilter(nodeEventFilter()).
		Complete(r)
}

// nodeEventFilter filters node events to only react to meaningful changes.
func nodeEventFilter() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true // New node added
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true // Node removed
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, ok1 := e.ObjectOld.(*corev1.Node)
			newNode, ok2 := e.ObjectNew.(*corev1.Node)
			if !ok1 || !ok2 {
				return false
			}
			// Only reconcile if addresses or provider ID changed
			return addressesChanged(oldNode, newNode) ||
				oldNode.Spec.ProviderID != newNode.Spec.ProviderID
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}

// parseHetznerProviderID extracts the server ID from a Hetzner provider ID.
// Format: hcloud://SERVER_ID
func parseHetznerProviderID(providerID string) (int64, error) {
	if !strings.HasPrefix(providerID, "hcloud://") {
		return 0, fmt.Errorf("not a hcloud provider ID: %s", providerID)
	}
	idStr := strings.TrimPrefix(providerID, "hcloud://")
	return strconv.ParseInt(idStr, 10, 64)
}

// isControlPlaneNode checks if a node is a control-plane (server) node.
func isControlPlaneNode(node *corev1.Node) bool {
	_, hasCP := node.Labels["node-role.kubernetes.io/control-plane"]
	_, hasMaster := node.Labels["node-role.kubernetes.io/master"]
	// RKE2 also uses this label for server nodes
	_, hasServer := node.Labels["node-role.kubernetes.io/etcd"]
	return hasCP || hasMaster || hasServer
}

// addressesChanged checks if the node's addresses changed.
func addressesChanged(old, new *corev1.Node) bool {
	if len(old.Status.Addresses) != len(new.Status.Addresses) {
		return true
	}
	oldAddrs := make(map[string]string)
	for _, a := range old.Status.Addresses {
		oldAddrs[string(a.Type)] = a.Address
	}
	for _, a := range new.Status.Addresses {
		if oldAddrs[string(a.Type)] != a.Address {
			return true
		}
	}
	return false
}

// countServerNodes counts how many nodes are control-plane nodes.
func countServerNodes(nodes []firewall.NodeInfo) int {
	count := 0
	for _, n := range nodes {
		if n.IsServer {
			count++
		}
	}
	return count
}

// mapKeyForNode creates a reconcile request key for a node.
func mapKeyForNode(node *corev1.Node) []reconcile.Request {
	return []reconcile.Request{
		{NamespacedName: types.NamespacedName{Name: node.Name}},
	}
}
