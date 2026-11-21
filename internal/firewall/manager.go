package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Stats contains aggregated packet counters from all CPUs.
type Stats struct {
	ProcessedIPv4 uint64
	Dropped       uint64
}

// portRule must match the 4-byte C struct in xdp_firewall.c:
// protocol (1 byte), pad (1 byte), destination_port (2 bytes).
type portRule struct {
	Protocol        uint8
	Pad             uint8
	DestinationPort uint16
}

// Manager controls the loaded XDP program and its eBPF maps.
type Manager struct {
	objs     netguardObjects
	xdpLink  link.Link
	cpuCount int
}

// NewManager loads NetGuard and attaches XDP to the named interface.
func NewManager(interfaceName string) (*Manager, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find interface %q: %w", interfaceName, err)
	}

	cpuCount, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPU count: %w", err)
	}

	var objs netguardObjects
	if err := loadNetguardObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.NetguardXdp,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach XDP to %s: %w", interfaceName, err)
	}

	return &Manager{
		objs:     objs,
		xdpLink:  xdpLink,
		cpuCount: cpuCount,
	}, nil
}

// ipToKey converts an IPv4 address into the 4-byte key used by eBPF.
func ipToKey(ip string) (uint32, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, fmt.Errorf("invalid IP address: %q", ip)
	}

	ipv4 := parsed.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("IPv4 address required: %q", ip)
	}

	return binary.NativeEndian.Uint32(ipv4), nil
}

// Block adds an IPv4 address to the blocklist.
func (m *Manager) Block(ip string) error {
	key, err := ipToKey(ip)
	if err != nil {
		return err
	}

	value := uint8(1)
	if err := m.objs.BlockedIps.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("block %s: %w", ip, err)
	}

	return nil
}

// Unblock removes an IPv4 address from the blocklist.
func (m *Manager) Unblock(ip string) error {
	key, err := ipToKey(ip)
	if err != nil {
		return err
	}

	if err := m.objs.BlockedIps.Delete(key); err != nil {
		return fmt.Errorf("unblock %s: %w", ip, err)
	}

	return nil
}

// makePortRule validates a protocol and creates the matching eBPF map key.
func makePortRule(protocol string, port uint16) (portRule, error) {
	if port == 0 {
		return portRule{}, fmt.Errorf("port must be between 1 and 65535")
	}

	var proto uint8

	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "TCP":
		proto = 6
	case "UDP":
		proto = 17
	default:
		return portRule{}, fmt.Errorf("unsupported protocol %q: use TCP or UDP", protocol)
	}

	return portRule{
		Protocol:        proto,
		Pad:             0,
		DestinationPort: port,
	}, nil
}

// BlockPort adds a TCP or UDP destination port to the blocklist.
func (m *Manager) BlockPort(protocol string, port uint16) error {
	key, err := makePortRule(protocol, port)
	if err != nil {
		return err
	}

	value := uint8(1)
	if err := m.objs.BlockedPorts.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("block %s port %d: %w", protocol, port, err)
	}

	return nil
}

// UnblockPort removes a TCP or UDP destination port from the blocklist.
func (m *Manager) UnblockPort(protocol string, port uint16) error {
	key, err := makePortRule(protocol, port)
	if err != nil {
		return err
	}

	if err := m.objs.BlockedPorts.Delete(key); err != nil {
		return fmt.Errorf("unblock %s port %d: %w", protocol, port, err)
	}

	return nil
}

// GetStats reads and aggregates per-CPU packet counters.
func (m *Manager) GetStats() (Stats, error) {
	var stats Stats

	for key := uint32(0); key < 2; key++ {
		values := make([]uint64, m.cpuCount)

		if err := m.objs.PacketStats.Lookup(&key, &values); err != nil {
			return Stats{}, fmt.Errorf("read packet counter %d: %w", key, err)
		}

		var total uint64
		for _, value := range values {
			total += value
		}

		if key == 0 {
			stats.ProcessedIPv4 = total
		} else {
			stats.Dropped = total
		}
	}

	return stats, nil
}

// Close detaches XDP and releases the loaded eBPF objects.
func (m *Manager) Close() error {
	var linkErr error
	if m.xdpLink != nil {
		linkErr = m.xdpLink.Close()
	}

	objErr := m.objs.Close()
	return errors.Join(linkErr, objErr)
}
