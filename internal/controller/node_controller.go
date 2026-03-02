package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/atroo/hetzner-firewall-operator/internal/config"
	"github.com/atroo/hetzner-firewall-operator/internal/firewall"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// NodeReconciler watches Kubernetes nodes and reconciles Hetzner firewall rules.
type NodeReconciler struct {
	client.Client
	fwClient *firewall.Client
	cfg      config.Config
	logger   *slog.Logger

	// lastReconcile tracks the last successful reconciliation time
	// to implement rate limiting.
	lastReconcile time.Time
}

// NewNodeReconciler creates a new NodeReconciler.
func NewNodeReconciler(
	k8sClient client.Client,
	fwClient *firewall.Client,
	cfg config.Config,
	logger *slog.Logger,
) *NodeReconciler {
	return &NodeReconciler{
		Client:   k8sClient,
		fwClient: fwClient,
		cfg:      cfg,
		logger:   logger,
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

	// Convert K8s nodes to NodeInfo
	nodes, err := r.extractNodeInfos(nodeList.Items)
	if err != nil {
		r.logger.Error("failed to extract node info", "error", err)
		return reconcile.Result{RequeueAfter: 30 * time.Second}, err
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

// extractNodeInfos converts K8s Node objects to firewall.NodeInfo.
func (r *NodeReconciler) extractNodeInfos(nodes []corev1.Node) ([]firewall.NodeInfo, error) {
	var infos []firewall.NodeInfo

	for _, node := range nodes {
		// Extract Hetzner server ID from providerID
		// Format: hcloud://SERVER_ID
		serverID, err := parseHetznerProviderID(node.Spec.ProviderID)
		if err != nil {
			r.logger.Debug("skipping node without Hetzner provider ID",
				"node", node.Name,
				"providerID", node.Spec.ProviderID,
			)
			continue
		}

		info := firewall.NodeInfo{
			Name:     node.Name,
			ServerID: serverID,
			IsServer: isControlPlaneNode(&node),
		}

		// Extract IPs from node addresses
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeExternalIP || addr.Type == corev1.NodeInternalIP {
				ip := net.ParseIP(addr.Address)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					info.IPv4 = ip
				} else {
					// For IPv6, Hetzner assigns a /64 network
					info.IPv6Net = &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(64, 128),
					}
				}
			}
		}

		if info.IPv4 != nil || info.IPv6Net != nil {
			infos = append(infos, info)
		} else {
			r.logger.Warn("node has no usable IP addresses", "node", node.Name)
		}
	}

	return infos, nil
}

// SetupWithManager registers the controller with the manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
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
