package sshclient

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrInvalidBind reports a bind value that cannot be resolved locally.
// Callers must treat this as a configuration error and must not dial.
var ErrInvalidBind = errors.New("invalid bind")

var (
	listInterfaces = net.Interfaces
	interfaceAddrs = func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}
)

// ResolveBind turns a bind value (literal IP or interface name) into a local
// TCP address suitable for net.Dialer.LocalAddr. An empty bind is a no-op.
// destHost may be a hostname, IP, or host:port; hostnames do not trigger DNS.
func ResolveBind(bind, destHost string) (net.Addr, error) {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		return nil, nil
	}

	if addr, ok := parseLiteralBindIP(bind); ok {
		return addr, nil
	}

	return resolveInterfaceBind(bind, destIP(destHost))
}

func parseLiteralBindIP(bind string) (*net.TCPAddr, bool) {
	host := strings.TrimSpace(bind)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	zone := ""
	if i := strings.LastIndex(host, "%"); i >= 0 {
		zone = host[i+1:]
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	return &net.TCPAddr{IP: ip, Zone: zone}, true
}

func destIP(destHost string) net.IP {
	host := strings.TrimSpace(destHost)
	if host == "" {
		return nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

func resolveInterfaceBind(name string, dest net.IP) (*net.TCPAddr, error) {
	ifaces, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("%w: list interfaces: %v", ErrInvalidBind, err)
	}
	var found *net.Interface
	for i := range ifaces {
		if ifaces[i].Name == name {
			found = &ifaces[i]
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%w: interface %q not found", ErrInvalidBind, name)
	}
	addrs, err := interfaceAddrs(*found)
	if err != nil {
		return nil, fmt.Errorf("%w: interface %q addresses: %v", ErrInvalidBind, name, err)
	}

	want4 := dest != nil && dest.To4() != nil
	want6 := dest != nil && dest.To4() == nil
	allowLinkLocal := dest != nil && dest.IsLinkLocalUnicast()
	allowLoopback := dest != nil && dest.IsLoopback()

	var candidates []net.IP
	for _, a := range addrs {
		ip := ipFromAddr(a)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if want4 && ip.To4() == nil {
			continue
		}
		if want6 && ip.To4() != nil {
			continue
		}
		if ip.IsLoopback() && !allowLoopback {
			continue
		}
		if ip.IsLinkLocalUnicast() && !allowLinkLocal {
			continue
		}
		candidates = append(candidates, ip)
	}

	if ip := pickBindIP(candidates); ip != nil {
		return &net.TCPAddr{IP: ip, Zone: zoneFor(ip, name)}, nil
	}
	if dest != nil {
		return nil, fmt.Errorf("%w: interface %q has no usable %s address", ErrInvalidBind, name, ipFamilyName(dest))
	}
	return nil, fmt.Errorf("%w: interface %q has no usable address", ErrInvalidBind, name)
}

func pickBindIP(candidates []net.IP) net.IP {
	var first4, first6 net.IP
	for _, ip := range candidates {
		if !ip.IsGlobalUnicast() {
			continue
		}
		if ip.To4() != nil {
			if first4 == nil {
				first4 = ip
			}
			continue
		}
		if first6 == nil {
			first6 = ip
		}
	}
	if first4 != nil {
		return first4
	}
	if first6 != nil {
		return first6
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return nil
}

func zoneFor(ip net.IP, iface string) string {
	if ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
		return iface
	}
	return ""
}

func ipFamilyName(ip net.IP) string {
	if ip != nil && ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		s := a.String()
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		host := strings.TrimPrefix(s, "[")
		host = strings.TrimSuffix(host, "]")
		if i := strings.LastIndex(host, "%"); i >= 0 {
			host = host[:i]
		}
		return net.ParseIP(host)
	}
}
