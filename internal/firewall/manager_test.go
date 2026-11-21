package firewall

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIPToKey(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name:    "valid private IPv4",
			ip:      "10.10.0.2",
			wantErr: false,
		},
		{
			name:    "valid localhost IPv4",
			ip:      "127.0.0.1",
			wantErr: false,
		},
		{
			name:    "valid public IPv4",
			ip:      "8.8.8.8",
			wantErr: false,
		},
		{
			name:    "invalid IP",
			ip:      "not-an-ip",
			wantErr: true,
		},
		{
			name:    "IPv6 address",
			ip:      "2001:db8::1",
			wantErr: true,
		},
		{
			name:    "empty address",
			ip:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipToKey(tt.ip)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ipToKey(%q) error = %v, wantErr %v",
					tt.ip, err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			parsed := net.ParseIP(tt.ip).To4()
			gotBytes := make([]byte, 4)
			binary.NativeEndian.PutUint32(gotBytes, got)

			for i := range parsed {
				if gotBytes[i] != parsed[i] {
					t.Errorf("incorrect key bytes: got %v, want %v",
						gotBytes, parsed)
					break
				}
			}
		})
	}
}
