package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

func TestTSNetHTTPAndHTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-node tsnet integration test")
	}
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "test-network.ts.net",
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	control.SetGlobalAppCaps(testCaps(
		`{"target":"acme","repositories":["api"]}`,
		`{"target":"acme","permissions":{"contents":"read"}}`,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server := startTSNetNode(t, ctx, control.BaseURL(), "broker")
	client := startTSNetNode(t, ctx, control.BaseURL(), "client")
	local, err := server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now
	_, github := newFakeGitHub(t, now)
	app := testApp(t, github, nil, local.WhoIs, now)
	issuer := newLocalCertIssuer(t)
	tsnet.TestHooks.LocalBackend(server).ForTest().ConfigureCerts(issuer.getCert)

	httpListener, err := server.Listen("tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	httpsListener, err := server.ListenTLS("tcp", ":443")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: app}
	httpsServer := &http.Server{Handler: app}
	go httpServer.Serve(httpListener)
	go httpsServer.Serve(httpsListener)
	t.Cleanup(func() {
		httpServer.Close()
		httpsServer.Close()
	})

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: client.Dial,
			TLSClientConfig: &tls.Config{
				RootCAs: issuer.pool(),
			},
		},
	}
	for _, endpoint := range []string{
		"http://broker.test-network.ts.net/token/acme",
		"https://broker.test-network.ts.net/token/acme",
	} {
		var response *http.Response
		var body []byte
		for ctx.Err() == nil {
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err = httpClient.Do(request)
			if err == nil {
				body, err = io.ReadAll(response.Body)
				response.Body.Close()
				if err == nil && response.StatusCode == http.StatusOK {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if response == nil || response.StatusCode != http.StatusOK || string(body) != "installation-token\n" {
			t.Fatalf("%s returned response=%v body=%q context=%v", endpoint, response, body, ctx.Err())
		}
	}
}

func startTSNetNode(t *testing.T, ctx context.Context, controlURL, hostname string) *tsnet.Server {
	t.Helper()
	dir := filepath.Join(t.TempDir(), hostname)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	server := &tsnet.Server{
		ControlURL: controlURL,
		Dir:        dir,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
	}
	t.Cleanup(func() { server.Close() })
	if _, err := server.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return server
}

type localCertIssuer struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newLocalCertIssuer(t *testing.T) *localCertIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tsgh test root"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &localCertIssuer{root: root, rootKey: key}
}

func (i *localCertIssuer) getCert(hostname string) (*ipnlocal.TLSCertKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.root, &key.PublicKey, i.rootKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &ipnlocal.TLSCertKeyPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func (i *localCertIssuer) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(i.root)
	return pool
}
