package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dwivedyarvind67/netguard/internal/firewall"
)

type IPRequest struct {
	IP string `json:"ip"`
}

type PortRequest struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// FirewallManager describes the operations required by the API.
type FirewallManager interface {
	Block(ip string) error
	Unblock(ip string) error
	BlockPort(protocol string, port uint16) error
	UnblockPort(protocol string, port uint16) error
	GetStats() (firewall.Stats, error)
}

// newHandler creates the HTTP API independently of XDP.
func newHandler(manager FirewallManager) http.Handler {
	mux := http.NewServeMux()

	// Block an IPv4 address.
	mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Use POST", http.StatusMethodNotAllowed)
			return
		}

		var req IPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if err := manager.Block(req.IP); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"message": fmt.Sprintf("Blocked IP %s", req.IP),
		})
	})

	// Unblock an IPv4 address.
	mux.HandleFunc("/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Use DELETE", http.StatusMethodNotAllowed)
			return
		}

		var req IPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if err := manager.Unblock(req.IP); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"message": fmt.Sprintf("Unblocked IP %s", req.IP),
		})
	})

	// Block a TCP or UDP destination port.
	mux.HandleFunc("/block-port", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Use POST", http.StatusMethodNotAllowed)
			return
		}

		var req PortRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Port < 1 || req.Port > 65535 {
			http.Error(w, "Port must be between 1 and 65535", http.StatusBadRequest)
			return
		}

		if err := manager.BlockPort(req.Protocol, uint16(req.Port)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"message": fmt.Sprintf(
				"Blocked %s destination port %d",
				req.Protocol,
				req.Port,
			),
		})
	})

	// Unblock a TCP or UDP destination port.
	mux.HandleFunc("/unblock-port", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Use DELETE", http.StatusMethodNotAllowed)
			return
		}

		var req PortRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Port < 1 || req.Port > 65535 {
			http.Error(w, "Port must be between 1 and 65535", http.StatusBadRequest)
			return
		}

		if err := manager.UnblockPort(req.Protocol, uint16(req.Port)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"message": fmt.Sprintf(
				"Unblocked %s destination port %d",
				req.Protocol,
				req.Port,
			),
		})
	})

	// Read packet statistics.
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Use GET", http.StatusMethodNotAllowed)
			return
		}

		stats, err := manager.GetStats()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, stats)
	})

	return mux
}

func main() {
	manager, err := firewall.NewManager("veth-host")
	if err != nil {
		log.Fatalf("Failed to start NetGuard: %v", err)
	}
	defer manager.Close()

	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           newHandler(manager),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Println("NetGuard API listening on http://127.0.0.1:8080")
		if err := server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Printf("API server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Stopping NetGuard...")
	if err := server.Close(); err != nil {
		log.Printf("API shutdown error: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("JSON response error: %v", err)
	}
}
