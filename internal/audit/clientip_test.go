package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		hdr    map[string]string
		want   string
	}{
		{"loopback v4 + CF v4", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "198.51.100.7"},
		{"loopback v6 + CF v4", "[::1]:1234", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "198.51.100.7"},
		{"loopback v4 + CF v6", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "2001:db8::1"}, "2001:db8::1"},
		{"loopback v6 + CF v6", "[::1]:1234", map[string]string{"CF-Connecting-IP": "2001:db8::1"}, "2001:db8::1"},
		{"loopback + ugyldig", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "not-an-ip"}, "127.0.0.1"},
		{"loopback + tom", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": ""}, "127.0.0.1"},
		{"loopback + ingen header", "127.0.0.1:1234", nil, "127.0.0.1"},
		{"loopback + komma", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4, 5.6.7.8"}, "127.0.0.1"},
		{"loopback + mellomrom", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": " 1.2.3.4"}, "127.0.0.1"},
		{"loopback + mellomrom bak", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4 "}, "127.0.0.1"},
		{"loopback + port", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4:80"}, "127.0.0.1"},
		{"LAN + CF", "192.168.1.5:1", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "192.168.1.5"},
		{"offentlig + CF", "203.0.113.9:1", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "203.0.113.9"},
		{"RemoteAddr uten port", "203.0.113.9", nil, "203.0.113.9"},
		{"IPv4-mapped loopback + CF", "[::ffff:127.0.0.1]:1234", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "198.51.100.7"},
		{"zone-ID + CF", "[fe80::1%eth0]:1234", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "fe80::1%eth0"},
		{"loopback uten port + CF", "127.0.0.1", map[string]string{"CF-Connecting-IP": "198.51.100.7"}, "198.51.100.7"},
	}
	spoof := []string{"X-Forwarded-For", "X-Real-IP", "True-Client-IP"}
	for _, tc := range tests {
		for _, withSpoof := range []bool{false, true} {
			name := tc.name
			if withSpoof {
				name += " + spoofede headere"
			}
			t.Run(name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = tc.remote
				for k, v := range tc.hdr {
					r.Header.Set(k, v)
				}
				if withSpoof {
					for _, h := range spoof {
						r.Header.Set(h, "9.9.9.9")
					}
				}
				if got := ClientIP(r); got != tc.want {
					t.Errorf("ClientIP = %q, want %q", got, tc.want)
				}
			})
		}
	}
}
