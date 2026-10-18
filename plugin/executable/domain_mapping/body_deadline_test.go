package domain_mapping

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPIReadDeadlineReleasesIncompleteRequestBodies(t *testing.T) {
	for _, path := range []string{
		"/v1/lookup?ip=203.0.113.1&view=full",
		"/v1/lookup?ip=203.0.113.1&view=route",
		"/v1/stats",
	} {
		for _, body := range []struct {
			name string
			wire string
		}{
			{"content-length", "Content-Length: 1000\r\n\r\nx"},
			{"chunked-data", "Transfer-Encoding: chunked\r\n\r\n4\r\nx"},
			{"chunked-trailer", "Transfer-Encoding: chunked\r\nTrailer: X-Trace\r\n\r\n0\r\nX-Trace:"},
		} {
			t.Run(path+"/"+body.name, func(t *testing.T) {
				p, now := testPlugin(t, Args{API: APIArgs{Timeout: 50, MaxConcurrent: 1}})
				ip := netip.MustParseAddr("203.0.113.1")
				for i := 0; i < 32; i++ {
					p.index.put(netip.Addr{}, ip, Candidate{Domain: fmt.Sprintf("d%d.%s.example", i, strings.Repeat("x", 60)), Source: "a", ObservedAt: *now, ExpiresAt: now.Add(time.Minute)})
				}
				returned := make(chan struct{}, 1)
				api := p.API()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					api.ServeHTTP(w, req)
					returned <- struct{}{}
				}))
				defer server.Close()
				client := apiIncompleteBodyClient(t, server.URL, path, body.wire)
				defer client.Close()
				select {
				case <-returned:
				case <-time.After(time.Second):
					t.Fatal("incomplete request body retained the API handler past its deadline")
				}
				if p.apiActive.Load() != 0 {
					t.Fatal("request body timeout leaked API admission")
				}
				// The small route/stats response may return from the handler before
				// net/http starts draining the body. Its final flush must be bounded too.
				apiRequireRemoteClose(t, client)
				response, err := server.Client().Get(server.URL + "/v1/lookup?ip=203.0.113.1&view=route")
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("normal lookup did not recover: HTTP %d", response.StatusCode)
				}
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestAPIReadDeadlineAlsoBoundsRejectedRequestBodies(t *testing.T) {
	p, _ := testPlugin(t, Args{API: APIArgs{Timeout: 50, MaxConcurrent: 1}})
	if !p.apiSlots.TryAcquire(1) {
		t.Fatal("cannot occupy API capacity")
	}
	defer p.apiSlots.Release(1)
	server := httptest.NewServer(p.API())
	defer server.Close()
	client := apiIncompleteBodyClient(t, server.URL, "/v1/lookup?ip=203.0.113.1&view=route", "Content-Length: 1000\r\n\r\n")
	defer client.Close()
	apiRequireRemoteClose(t, client)
	if p.apiRejected.Load() != 1 || p.apiActive.Load() != 0 {
		t.Fatalf("unexpected admission state: rejected=%d active=%d", p.apiRejected.Load(), p.apiActive.Load())
	}
}

func apiIncompleteBodyClient(t *testing.T, serverURL, path, body string) net.Conn {
	t.Helper()
	client, err := net.DialTimeout("tcp", strings.TrimPrefix(serverURL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		client.Close()
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: localhost\r\n%s", path, body); err != nil {
		client.Close()
		t.Fatal(err)
	}
	return client
}

func apiRequireRemoteClose(t *testing.T, client net.Conn) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, client); err != nil {
		t.Fatalf("server failed to close incomplete request body within its budget: %v", err)
	}
}

func TestAPIReadDeadlineDoesNotPoisonKeepAlive(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			p, _ := testPlugin(t, Args{API: APIArgs{Timeout: 50}})
			server := httptest.NewUnstartedServer(p.API())
			var connections atomic.Int32
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.Start()
			defer server.Close()
			for i := 0; i < 2; i++ {
				req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/lookup?ip=203.0.113.1&view=route", strings.NewReader("ignored body"))
				if err != nil {
					t.Fatal(err)
				}
				if chunked {
					req.ContentLength = -1
				}
				response, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK {
					t.Fatalf("keep-alive lookup failed: HTTP %d %v", response.StatusCode, err)
				}
				if i == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			}
			if connections.Load() != 1 {
				t.Fatalf("request deadline prevented connection reuse: connections=%d", connections.Load())
			}
		})
	}
}
