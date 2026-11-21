package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dwivedyarvind67/netguard/internal/firewall"
)

// fakeFirewall simulates the real firewall manager.
type fakeFirewall struct {
	blockedIPs   map[string]bool
	blockedPorts map[string]bool
	stats        firewall.Stats
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{
		blockedIPs:   make(map[string]bool),
		blockedPorts: make(map[string]bool),
		stats: firewall.Stats{
			ProcessedIPv4: 10,
			Dropped:       3,
		},
	}
}

func (f *fakeFirewall) Block(ip string) error {
	if ip == "" {
		return errors.New("invalid IP")
	}
	f.blockedIPs[ip] = true
	return nil
}

func (f *fakeFirewall) Unblock(ip string) error {
	if !f.blockedIPs[ip] {
		return errors.New("IP not found")
	}
	delete(f.blockedIPs, ip)
	return nil
}

func portKey(protocol string, port uint16) string {
	return strings.ToUpper(protocol) + ":" + string(rune(port))
}

func (f *fakeFirewall) BlockPort(protocol string, port uint16) error {
	if protocol != "TCP" && protocol != "UDP" &&
		protocol != "tcp" && protocol != "udp" {
		return errors.New("unsupported protocol")
	}
	if port == 0 {
		return errors.New("invalid port")
	}

	f.blockedPorts[portKey(protocol, port)] = true
	return nil
}

func (f *fakeFirewall) UnblockPort(protocol string, port uint16) error {
	key := portKey(protocol, port)
	if !f.blockedPorts[key] {
		return errors.New("port rule not found")
	}
	delete(f.blockedPorts, key)
	return nil
}

func (f *fakeFirewall) GetStats() (firewall.Stats, error) {
	return f.stats, nil
}

func TestBlockEndpoint(t *testing.T) {
	manager := newFakeFirewall()
	handler := newHandler(manager)

	req := httptest.NewRequest(
		http.MethodPost,
		"/block",
		strings.NewReader(`{"ip":"10.10.0.2"}`),
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if !manager.blockedIPs["10.10.0.2"] {
		t.Fatal("IP was not added to blocked list")
	}
}

func TestUnblockEndpoint(t *testing.T) {
	manager := newFakeFirewall()
	manager.blockedIPs["10.10.0.2"] = true

	handler := newHandler(manager)

	req := httptest.NewRequest(
		http.MethodDelete,
		"/unblock",
		strings.NewReader(`{"ip":"10.10.0.2"}`),
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if manager.blockedIPs["10.10.0.2"] {
		t.Fatal("IP was not removed from blocked list")
	}
}

func TestBlockPortEndpoint(t *testing.T) {
	manager := newFakeFirewall()
	handler := newHandler(manager)

	req := httptest.NewRequest(
		http.MethodPost,
		"/block-port",
		strings.NewReader(`{"protocol":"TCP","port":443}`),
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if !manager.blockedPorts[portKey("TCP", 443)] {
		t.Fatal("TCP port 443 was not blocked")
	}
}

func TestUnblockPortEndpoint(t *testing.T) {
	manager := newFakeFirewall()
	manager.blockedPorts[portKey("UDP", 53)] = true

	handler := newHandler(manager)

	req := httptest.NewRequest(
		http.MethodDelete,
		"/unblock-port",
		strings.NewReader(`{"protocol":"UDP","port":53}`),
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if manager.blockedPorts[portKey("UDP", 53)] {
		t.Fatal("UDP port 53 was not unblocked")
	}
}

func TestInvalidPort(t *testing.T) {
	manager := newFakeFirewall()
	handler := newHandler(manager)

	req := httptest.NewRequest(
		http.MethodPost,
		"/block-port",
		strings.NewReader(`{"protocol":"TCP","port":70000}`),
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestStatsEndpoint(t *testing.T) {
	manager := newFakeFirewall()
	handler := newHandler(manager)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	expected := `{"ProcessedIPv4":10,"Dropped":3}`
	if strings.TrimSpace(rec.Body.String()) != expected {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}

func TestInvalidJSON(t *testing.T) {
	manager := newFakeFirewall()
	handler := newHandler(manager)

	req := httptest.NewRequest(
		http.MethodPost,
		"/block",
		strings.NewReader(`not-json`),
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestWrongHTTPMethod(t *testing.T) {
	manager := newFakeFirewall()
	handler := newHandler(manager)

	req := httptest.NewRequest(http.MethodGet, "/block", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rec.Code)
	}
}
