package provider

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"aurasplit/internal/profile"
)

func useWARPServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(handler)
	original := warpEndpoint
	warpEndpoint = s.URL
	t.Cleanup(func() { warpEndpoint = original; s.Close() })
	return s
}

func warpResponse(public, host string) map[string]any {
	return map[string]any{"token": "unused", "config": map[string]any{
		"peers":     []any{map[string]any{"public_key": public, "endpoint": map[string]string{"host": host}}},
		"interface": map[string]any{"addresses": map[string]string{"v4": "172.16.0.2", "v6": "2606:4700:110::2"}},
		"client_id": base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
	}}
}

func TestRegisterWARP(t *testing.T) {
	for _, tc := range []struct {
		host, want string
		status     int
	}{
		{"", "engage.cloudflareclient.com:2408", 200},
		{"engage.cloudflareclient.com", "engage.cloudflareclient.com:2408", 201},
		{"example.test:1234", "example.test:1234", 200},
		{"2001:db8::1", "[2001:db8::1]:2408", 200},
		{"[2001:db8::1]", "[2001:db8::1]:2408", 200},
	} {
		t.Run(tc.want+tc.host, func(t *testing.T) {
			public := testKey(t)
			var sentKey string
			s := useWARPServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("User-Agent") != "okhttp/3.12.1" || r.Header.Get("CF-Client-Version") != "a-6.30-3596" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("incorrect request method or headers")
				}
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid request body")
					return
				}
				if len(body) != 7 || body["model"] != "PC" || body["locale"] != "en_US" {
					t.Error("incorrect registration fields")
				}
				for _, field := range []string{"install_id", "fcm_token"} {
					if value, ok := body[field]; !ok || value != "" {
						t.Error("missing empty registration field")
					}
				}
				if serial, err := hex.DecodeString(body["serial_number"]); err != nil || len(serial) == 0 {
					t.Error("invalid random serial")
				}
				stamp, err := time.Parse("2006-01-02T15:04:05.000Z", body["tos"])
				if err != nil || time.Since(stamp) > time.Minute || time.Until(stamp) > time.Second {
					t.Error("invalid timestamp")
				}
				sentKey = body["key"]
				if !validKey(sentKey) {
					t.Error("invalid public key")
				}
				w.WriteHeader(tc.status)
				if err := json.NewEncoder(w).Encode(warpResponse(public, tc.host)); err != nil {
					t.Error(err)
				}
			})
			// A nil client also uses the test endpoint, never the real API.
			var client *http.Client
			if tc.status == 201 {
				client = s.Client()
			}
			wg, err := RegisterWARP(context.Background(), client)
			if err != nil {
				t.Fatal(err)
			}
			privateBytes, err := base64.StdEncoding.DecodeString(wg.PrivateKey)
			if err != nil {
				t.Fatal("invalid private key encoding")
			}
			private, err := ecdh.X25519().NewPrivateKey(privateBytes)
			if err != nil || base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) != sentKey {
				t.Fatal("registered public key does not match local private key")
			}
			if wg.Endpoint != tc.want || wg.PeerPublicKey != public || wg.MTU != 1280 || !reflect.DeepEqual(wg.Reserved, []byte{1, 2, 3}) || !reflect.DeepEqual(wg.DNS, []string{"1.1.1.1", "1.0.0.1"}) || !reflect.DeepEqual(wg.Addresses, []string{"172.16.0.2/32", "2606:4700:110::2/128"}) {
				t.Fatal("incorrect WARP profile")
			}
			if err := (&profile.Profile{Provider: profile.ProviderWARP, WireGuard: wg}).Validate(); err != nil {
				t.Fatal("profile validation failed")
			}
		})
	}
}

func TestRegisterWARPErrors(t *testing.T) {
	secret := testKey(t)
	for _, name := range []string{"http", "json", "oversize", "missing peer", "bad key", "bad reserved", "missing address", "wrong family", "bad endpoint", "trailing JSON"} {
		t.Run(name, func(t *testing.T) {
			s := useWARPServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "http":
					w.WriteHeader(403)
					_, _ = io.WriteString(w, secret)
					return
				case "json":
					_, _ = io.WriteString(w, secret)
					return
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat(" ", (1<<20)+1))
					return
				}
				result := warpResponse(testKey(t), "example.test")
				result["token"] = secret
				config := result["config"].(map[string]any)
				switch name {
				case "missing peer":
					config["peers"] = []any{}
				case "bad key":
					config["peers"].([]any)[0].(map[string]any)["public_key"] = secret + "!"
				case "bad reserved":
					config["client_id"] = secret
				case "missing address":
					config["interface"] = nil
				case "wrong family":
					config["interface"].(map[string]any)["addresses"] = map[string]string{"v4": "::1", "v6": "10.0.0.1"}
				case "bad endpoint":
					config["peers"].([]any)[0].(map[string]any)["endpoint"] = map[string]string{"host": secret + ":bad"}
				}
				_ = json.NewEncoder(w).Encode(result)
				if name == "trailing JSON" {
					_, _ = io.WriteString(w, "{}")
				}
			})
			wg, err := RegisterWARP(context.Background(), s.Client())
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error exposed key or token")
			}
			if !reflect.DeepEqual(wg, profile.WireGuard{}) {
				t.Fatal("partial profile on failure")
			}
		})
	}
}

type failingTransport struct{ secret string }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New(f.secret)
}

func TestRegisterWARPTransportErrorRedacted(t *testing.T) {
	secret := testKey(t)
	_, err := RegisterWARP(context.Background(), &http.Client{Transport: failingTransport{secret}})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("transport error was not redacted")
	}
}

func TestRegisterWARPCancellation(t *testing.T) {
	s := useWARPServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := RegisterWARP(ctx, s.Client())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("context deadline not preserved")
	}
}

// A redirect must not be followed (the second server is never contacted)
// and must be reported as an error, for every 3xx code.
func TestRegisterWARPRefusesRedirect(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			hit := false
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit = true
				_ = json.NewEncoder(w).Encode(warpResponse(testKey(t), ""))
			}))
			defer other.Close()
			s := useWARPServer(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, other.URL, code)
			})
			client := s.Client()
			wg, err := RegisterWARP(context.Background(), client)
			if err == nil || !strings.Contains(err.Error(), "redirect") {
				t.Fatalf("expected redirect error, got %v", err)
			}
			if hit {
				t.Fatal("redirect was followed")
			}
			if client.CheckRedirect != nil {
				t.Fatal("caller's client was modified")
			}
			if !reflect.DeepEqual(wg, profile.WireGuard{}) {
				t.Fatal("partial profile on failure")
			}
		})
	}
}
