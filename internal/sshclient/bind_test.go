package sshclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeAddr struct {
	s string
}

func (a fakeAddr) Network() string { return "ip+net" }
func (a fakeAddr) String() string  { return a.s }

func mustTCP(t *testing.T, addr net.Addr) *net.TCPAddr {
	t.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("got %#v", addr)
	}
	return tcp
}

func withFakeIfaces(t *testing.T, ifaces []net.Interface, addrs map[string][]net.Addr) {
	t.Helper()
	origList, origAddrs := listInterfaces, interfaceAddrs
	t.Cleanup(func() {
		listInterfaces = origList
		interfaceAddrs = origAddrs
	})
	listInterfaces = func() ([]net.Interface, error) {
		return ifaces, nil
	}
	interfaceAddrs = func(iface net.Interface) ([]net.Addr, error) {
		return addrs[iface.Name], nil
	}
}

func TestResolveBindEmpty(t *testing.T) {
	addr, err := ResolveBind("", "1.2.3.4")
	if err != nil || addr != nil {
		t.Fatalf("empty bind = %v, %v; want nil, nil", addr, err)
	}
}

func TestResolveBindLiteralIPv4(t *testing.T) {
	addr, err := ResolveBind("192.0.2.10", "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustTCP(t, addr).IP.String(); got != "192.0.2.10" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveBindLiteralIPv6Bracketed(t *testing.T) {
	addr, err := ResolveBind("[::1]", "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if tcp := mustTCP(t, addr); !tcp.IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("got %v", tcp.IP)
	}
}

func TestResolveBindLiteralIPv6Zone(t *testing.T) {
	addr, err := ResolveBind("fe80::1%en0", "fe80::2")
	if err != nil {
		t.Fatal(err)
	}
	if tcp := mustTCP(t, addr); !tcp.IP.Equal(net.ParseIP("fe80::1")) || tcp.Zone != "en0" {
		t.Fatalf("got %#v", tcp)
	}
}

func TestResolveBindInterfacePrefersGlobalIPv4(t *testing.T) {
	withFakeIfaces(t, []net.Interface{{Name: "en0"}}, map[string][]net.Addr{
		"en0": {
			fakeAddr{"fe80::1/64"},
			fakeAddr{"2001:db8::10/64"},
			fakeAddr{"192.0.2.8/24"},
			fakeAddr{"127.0.0.1/8"},
		},
	})
	addr, err := ResolveBind("en0", "example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustTCP(t, addr).IP.String(); got != "192.0.2.8" {
		t.Fatalf("got %s, want 192.0.2.8", got)
	}
}

func TestResolveBindInterfaceMatchesDestFamily(t *testing.T) {
	withFakeIfaces(t, []net.Interface{{Name: "en0"}}, map[string][]net.Addr{
		"en0": {
			fakeAddr{"192.0.2.8/24"},
			fakeAddr{"2001:db8::10/64"},
		},
	})
	addr, err := ResolveBind("en0", "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustTCP(t, addr).IP.String(); got != "2001:db8::10" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveBindInterfaceSkipsLinkLocalUnlessDestIs(t *testing.T) {
	withFakeIfaces(t, []net.Interface{{Name: "en0"}}, map[string][]net.Addr{
		"en0": {fakeAddr{"fe80::9/64"}},
	})
	_, err := ResolveBind("en0", "203.0.113.1")
	if !errors.Is(err, ErrInvalidBind) {
		t.Fatalf("got %v, want ErrInvalidBind", err)
	}

	addr, err := ResolveBind("en0", "fe80::2")
	if err != nil {
		t.Fatal(err)
	}
	if tcp := mustTCP(t, addr); !tcp.IP.Equal(net.ParseIP("fe80::9")) || tcp.Zone != "en0" {
		t.Fatalf("got %#v", tcp)
	}
}

func TestResolveBindInterfaceSkipsLoopbackUnlessDestIs(t *testing.T) {
	withFakeIfaces(t, []net.Interface{{Name: "lo0"}}, map[string][]net.Addr{
		"lo0": {fakeAddr{"127.0.0.1/8"}},
	})
	_, err := ResolveBind("lo0", "203.0.113.1")
	if !errors.Is(err, ErrInvalidBind) {
		t.Fatalf("got %v, want ErrInvalidBind", err)
	}
	addr, err := ResolveBind("lo0", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustTCP(t, addr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveBindMissingInterface(t *testing.T) {
	withFakeIfaces(t, nil, nil)
	_, err := ResolveBind("en0", "1.2.3.4")
	if !errors.Is(err, ErrInvalidBind) {
		t.Fatalf("got %v, want ErrInvalidBind", err)
	}
}

func TestConnectDirectUsesResolvedLocalAddr(t *testing.T) {
	orig := dialTCP
	t.Cleanup(func() { dialTCP = orig })
	var got net.Addr
	dialTCP = func(ctx context.Context, addr string, localAddr net.Addr, timeout time.Duration) (net.Conn, error) {
		got = localAddr
		return nil, errors.New("dial blocked")
	}
	c := &SSHClient{config: &Config{
		Host:                 "203.0.113.1",
		Port:                 "22",
		User:                 "u",
		Password:             "x",
		UseKeyAuth:           false,
		Bind:                 "192.0.2.10",
		AllowInsecureHostKey: true,
	}}
	err := c.ConnectDirect()
	if err == nil {
		t.Fatal("expected dial error")
	}
	if tcp := mustTCP(t, got); tcp.IP.String() != "192.0.2.10" {
		t.Fatalf("LocalAddr = %#v", got)
	}
}

func TestConnectDirectInvalidBindDoesNotDial(t *testing.T) {
	withFakeIfaces(t, nil, nil)
	orig := dialTCP
	t.Cleanup(func() { dialTCP = orig })
	dialed := false
	dialTCP = func(ctx context.Context, addr string, localAddr net.Addr, timeout time.Duration) (net.Conn, error) {
		dialed = true
		return nil, errors.New("should not dial")
	}
	c := &SSHClient{config: &Config{
		Host:                 "203.0.113.1",
		Port:                 "22",
		User:                 "u",
		Password:             "x",
		UseKeyAuth:           false,
		Bind:                 "en0",
		AllowInsecureHostKey: true,
	}}
	err := c.ConnectDirect()
	if !errors.Is(err, ErrInvalidBind) {
		t.Fatalf("got %v, want ErrInvalidBind", err)
	}
	if dialed {
		t.Fatal("dialed after invalid bind")
	}
}
