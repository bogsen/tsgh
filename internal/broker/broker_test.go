package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestScopeFromCaps(t *testing.T) {
	caps := testCaps(
		`{"target":"Acme","repositories":["api"]}`,
		`{"target":"acme","repositories":["web","API"]}`,
		`{"target":"acme","permissions":{"contents":"read","issues":"write"}}`,
		`{"target":"ACME","permissions":{"contents":"write","issues":"read"}}`,
		`{"target":"acme","githubUser":"Octocat"}`,
		`{"target":"other","repositories":["ignored"]}`,
	)
	scope, err := ScopeFromCaps(caps, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(scope.Repositories, ","), "API,web"; got != want {
		t.Fatalf("repositories = %q, want %q", got, want)
	}
	if scope.Permissions["contents"] != "write" || scope.Permissions["issues"] != "write" {
		t.Fatalf("permissions were not unioned: %#v", scope.Permissions)
	}
	if scope.GitHubUser != "Octocat" {
		t.Fatalf("github user = %q", scope.GitHubUser)
	}

	wildcard, err := ScopeFromCaps(testCaps(
		`{"target":"acme","repositories":["api","*"]}`,
		`{"target":"acme","permissions":{"contents":"read"}}`,
	), "acme")
	if err != nil || len(wildcard.Repositories) != 1 || wildcard.Repositories[0] != "*" {
		t.Fatalf("wildcard union = %#v, %v", wildcard.Repositories, err)
	}
}

func TestLoadConfigRequiresStateDir(t *testing.T) {
	t.Setenv("TSGH_GITHUB_APP_ID", "123")
	t.Setenv("TSGH_GITHUB_PRIVATE_KEY_FILE", "unused")
	t.Setenv("TSGH_STATE_DIR", "")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "TSGH_STATE_DIR") {
		t.Fatalf("LoadConfig error = %v", err)
	}
}

func TestScopeRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name string
		caps tailcfg.PeerCapMap
	}{
		{"combined", testCaps(`{"target":"acme","repositories":["api"],"permissions":{"contents":"read"}}`)},
		{"missing permissions", testCaps(`{"target":"acme","repositories":["api"]}`)},
		{"conflicting users", testCaps(
			`{"target":"acme","githubUser":"one"}`,
			`{"target":"acme","githubUser":"two"}`,
			`{"target":"acme","repositories":["api"]}`,
			`{"target":"acme","permissions":{"contents":"read"}}`,
		)},
		{"repository owner", testCaps(
			`{"target":"acme","repositories":["acme/api"]}`,
			`{"target":"acme","permissions":{"contents":"read"}}`,
		)},
		{"invalid level", testCaps(
			`{"target":"acme","repositories":["api"]}`,
			`{"target":"acme","permissions":{"contents":"owner"}}`,
		)},
		{"unknown field", testCaps(`{"target":"acme","githubUser":"one","future":true}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ScopeFromCaps(test.caps, "acme"); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestEncryptedStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyBytes := bytes.Repeat([]byte{7}, 32)
	store, err := NewStore(dir, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	credentials := OAuthCredentials{
		AccessToken:      "secret-access",
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshToken:     "secret-refresh",
		RefreshExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := store.PutCredentials("100", credentials); err != nil {
		t.Fatal(err)
	}
	record := ScopedToken{Token: "secret-scoped", NodeID: "node", Target: "acme", Actor: "octocat", ScopeKey: "scope", ExpiresAt: time.Now().Add(8 * time.Hour), RevokeAt: time.Now().Add(time.Hour)}
	if err := store.AddScoped(record); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(dir, "state.enc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-access", "secret-refresh", "secret-scoped"} {
		if bytes.Contains(ciphertext, []byte(secret)) {
			t.Fatalf("encrypted state contains %q", secret)
		}
	}
	reloaded, err := NewStore(dir, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Credentials("100")
	if !ok || got.AccessToken != credentials.AccessToken || len(reloaded.ScopedTokens()) != 1 {
		t.Fatalf("state did not round trip: %#v %#v", got, reloaded.ScopedTokens())
	}
	if _, err := NewStore(dir, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key unexpectedly decrypted state")
	}
}

type fakeGitHub struct {
	t          *testing.T
	server     *httptest.Server
	now        func() time.Time
	mu         sync.Mutex
	installs   int
	issued     int
	scoped     int
	revoked    int
	revokeFail int
	refreshed  int
	grantsGone int
	publicKey  *rsa.PublicKey
	challenge  string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newFakeGitHub(t *testing.T, now func() time.Time) (*fakeGitHub, *GitHub) {
	t.Helper()
	fake := &fakeGitHub{t: t, now: now}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(fake.server.Close)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	fake.publicKey = &privateKey.PublicKey
	return fake, &GitHub{
		HTTP:         fake.server.Client(),
		APIURL:       fake.server.URL,
		WebURL:       fake.server.URL,
		AppID:        123,
		ClientID:     "client",
		ClientSecret: "secret",
		PrivateKey:   privateKey,
		Now:          now,
	}
}

func (f *fakeGitHub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/orgs/acme/installation":
		if err := verifyJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), f.publicKey); err != nil {
			f.t.Errorf("installation lookup used an invalid app JWT: %v", err)
		}
		f.installs++
		io.WriteString(w, `{"id":42}`)
	case r.URL.Path == "/app/installations/42/access_tokens":
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if strings.Join(body.Repositories, ",") != "api" || body.Permissions["contents"] != "read" {
			f.t.Errorf("unexpected installation scope: %#v", body)
		}
		f.issued++
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(IssuedToken{Token: fmt.Sprintf("installation-token-%d", f.issued), ExpiresAt: f.now().Add(time.Hour)})
	case r.URL.Path == "/applications/client/token/scoped":
		username, password, ok := r.BasicAuth()
		if !ok || username != "client" || password != "secret" {
			f.t.Error("scoped token request did not use app basic auth")
		}
		var body struct {
			AccessToken  string            `json:"access_token"`
			Target       string            `json:"target"`
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.AccessToken != "base-token" || body.Target != "acme" || strings.Join(body.Repositories, ",") != "api" || body.Permissions["contents"] != "read" {
			f.t.Errorf("unexpected scoped token request: %#v", body)
		}
		f.scoped++
		json.NewEncoder(w).Encode(IssuedToken{Token: fmt.Sprintf("user-token-%d", f.scoped), ExpiresAt: f.now().Add(8 * time.Hour)})
	case r.URL.Path == "/applications/client/token" && r.Method == http.MethodDelete:
		f.revoked++
		if f.revokeFail > 0 {
			f.revokeFail--
			http.Error(w, "temporary failure", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/applications/client/grant" && r.Method == http.MethodDelete:
		f.grantsGone++
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/user":
		io.WriteString(w, `{"id":1,"login":"octocat"}`)
	case r.URL.Path == "/login/oauth/access_token":
		if err := r.ParseForm(); err != nil {
			f.t.Error(err)
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			f.refreshed++
		} else if f.challenge != "" {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
				f.t.Error("oauth token exchange did not use the PKCE verifier")
			}
		}
		io.WriteString(w, `{"access_token":"base-token","expires_in":28800,"refresh_token":"refresh-token","refresh_token_expires_in":15897600}`)
	default:
		http.NotFound(w, r)
	}
}

func verifyJWT(token string, publicKey *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a three-part JWT")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
}

func (f *fakeGitHub) counts() (installs, issued, scoped, revoked int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installs, f.issued, f.scoped, f.revoked
}

func TestInstallationTokenHandler(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fake, github := newFakeGitHub(t, func() time.Time { return now })
	var audit bytes.Buffer
	app := testAppWithAudit(t, github, nil, func(_ context.Context, remote string) (*apitype.WhoIsResponse, error) {
		nodeID, nodeName := "node-1", "client-one.example.ts.net."
		if strings.HasPrefix(remote, "other") {
			nodeID, nodeName = "node-2", "client-two.example.ts.net."
		}
		who := testWhoIs("100", nodeID, testCaps(
			`{"target":"acme","repositories":["api"]}`,
			`{"target":"acme","permissions":{"contents":"read"}}`,
		))
		who.Node.Name = nodeName
		who.UserProfile.LoginName = "alice@example.com"
		return who, nil
	}, func() time.Time { return now }, testAuditLog(&audit))

	for _, scheme := range []string{"http", "https"} {
		req := httptest.NewRequest(http.MethodPost, scheme+"://tsgh/token/acme", nil)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		if response.Code != http.StatusOK || response.Body.String() != "installation-token-1\n" {
			t.Fatalf("response = %d %q", response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("unexpected headers: %#v", response.Header())
		}
	}
	installs, issued, _, _ := fake.counts()
	if installs != 1 || issued != 1 {
		t.Fatalf("runtime cache missed: installations=%d issued=%d", installs, issued)
	}

	denied := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://tsgh/token/other", nil)
	app.ServeHTTP(denied, req)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d", denied.Code)
	}
	if after, _, _, _ := fake.counts(); after != installs {
		t.Fatal("denied request reached GitHub")
	}

	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil)
		req.RemoteAddr = "other:1234"
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		if response.Code != http.StatusOK || response.Body.String() != "installation-token-2\n" {
			t.Fatalf("other-node response = %d %q", response.Code, response.Body.String())
		}
	}
	installs, issued, _, _ = fake.counts()
	if installs != 1 || issued != 2 {
		t.Fatalf("node cache isolation failed: installations=%d issued=%d", installs, issued)
	}

	logText := audit.String()
	firstSum := sha256.Sum256([]byte("installation-token-1"))
	secondSum := sha256.Sum256([]byte("installation-token-2"))
	firstHash := base64.StdEncoding.EncodeToString(firstSum[:])
	secondHash := base64.StdEncoding.EncodeToString(secondSum[:])
	for _, field := range []string{
		"action=token.issue", "outcome=success", "outcome=denied", "reason=token_not_granted",
		"node_id=node-1", "node_name=client-one.example.ts.net.", "source_ip=192.0.2.1",
		"tailscale_user_id=100", "tailscale_user_login=alice@example.com", "target=acme",
		"token_type=installation", `token_hash="` + firstHash + `"`, "node_id=node-2", `token_hash="` + secondHash + `"`,
	} {
		if !strings.Contains(logText, field) {
			t.Errorf("audit log omitted %q:\n%s", field, logText)
		}
	}
	if strings.Count(logText, "action=token.issue") != 5 || strings.Count(logText, `token_hash="`+firstHash+`"`) != 2 || strings.Count(logText, `token_hash="`+secondHash+`"`) != 2 {
		t.Fatalf("unexpected audit event counts:\n%s", logText)
	}
	if strings.Contains(logText, "installation-token-") {
		t.Fatalf("audit log exposed an installation token:\n%s", logText)
	}
}

func TestInstallationTokenCachePrunesExpiredNodes(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	identity := caller{NodeID: "active-node"}
	scope := Scope{Target: "Acme", Repositories: []string{"api"}, Permissions: map[string]string{"contents": "read"}}
	activeKey := identity.NodeID + ":" + strings.ToLower(scope.Target) + ":" + scope.Key()
	app := &App{
		now: func() time.Time { return now },
		installationTokens: map[string]cachedInstallationToken{
			"expired-node": {Token: "expired", ExpiresAt: now.Add(-time.Minute)},
			"near-expiry":  {Token: "near", ExpiresAt: now.Add(time.Minute)},
			activeKey:      {Token: "active", ExpiresAt: now.Add(2 * time.Minute)},
		},
	}

	token, err := app.issueInstallationTokenLocked(context.Background(), identity, scope)
	if err != nil || token != "active" {
		t.Fatalf("cached token = %q, %v", token, err)
	}
	if len(app.installationTokens) != 1 {
		t.Fatalf("cache retained stale nodes: %#v", app.installationTokens)
	}
	if _, ok := app.installationTokens[activeKey]; !ok {
		t.Fatal("cache pruned the reusable token")
	}
}

func TestMissingInstallationResponse(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	_, github := newFakeGitHub(t, func() time.Time { return now })
	app := testApp(t, github, nil, func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return testWhoIs("100", "node-1", testCaps(
			`{"target":"nimsen","repositories":["api"]}`,
			`{"target":"nimsen","permissions":{"contents":"read"}}`,
		)), nil
	}, func() time.Time { return now })

	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://tsgh/token/nimsen", nil))
	if response.Code != http.StatusNotFound || response.Body.String() != "github app is not installed for target \"nimsen\"\n" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestAuthenticationAndFallbackIdentityAudit(t *testing.T) {
	t.Run("authentication failure", func(t *testing.T) {
		var audit bytes.Buffer
		app, err := NewApp(AppConfig{
			WhoIs:    func(context.Context, string) (*apitype.WhoIsResponse, error) { return nil, errors.New("not found") },
			GitHub:   &GitHub{},
			AuditLog: testAuditLog(&audit),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github/callback?code=oauth-secret&state=state-secret", nil)
		request.RemoteAddr = "[fd7a:115c:a1e0::1]:1234"
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		logText := audit.String()
		if response.Code != http.StatusUnauthorized || !strings.Contains(logText, "action=authentication") || !strings.Contains(logText, "outcome=denied") || !strings.Contains(logText, "status=401") || !strings.Contains(logText, "source_ip=fd7a:115c:a1e0::1") || !strings.Contains(logText, "reason=tailscale_identity_required") {
			t.Fatalf("unexpected authentication response or audit: status=%d\n%s", response.Code, logText)
		}
		for _, secret := range []string{"oauth-secret", "state-secret", "code=", "state="} {
			if strings.Contains(logText, secret) {
				t.Fatalf("authentication audit exposed %q:\n%s", secret, logText)
			}
		}
	})

	t.Run("node key fallback", func(t *testing.T) {
		var audit bytes.Buffer
		nodeKey := key.NewNode().Public()
		app, err := NewApp(AppConfig{
			WhoIs: func(context.Context, string) (*apitype.WhoIsResponse, error) {
				return &apitype.WhoIsResponse{Node: &tailcfg.Node{Key: nodeKey}}, nil
			},
			GitHub:   &GitHub{},
			AuditLog: testAuditLog(&audit),
		})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil))
		logText := audit.String()
		if response.Code != http.StatusForbidden || !strings.Contains(logText, "node_key="+nodeKey.String()) || strings.Contains(logText, "node_id=") {
			t.Fatalf("node-key fallback was not audited correctly: status=%d\n%s", response.Code, logText)
		}
	})
}

func TestTokenAuditError(t *testing.T) {
	var audit bytes.Buffer
	app, err := NewApp(AppConfig{
		WhoIs: func(context.Context, string) (*apitype.WhoIsResponse, error) {
			return testWhoIs("100", "node-1", testCaps(
				`{"target":"acme","githubUser":"octocat"}`,
				`{"target":"acme","repositories":["api"]}`,
				`{"target":"acme","permissions":{"contents":"read"}}`,
			)), nil
		},
		GitHub:   &GitHub{ClientID: "client", ClientSecret: "oauth-secret"},
		AuditLog: testAuditLog(&audit),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil))
	logText := audit.String()
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(logText, "action=token.issue") || !strings.Contains(logText, "outcome=error") || !strings.Contains(logText, "status=503") || !strings.Contains(logText, "reason=user_tokens_unconfigured") {
		t.Fatalf("unexpected token error response or audit: status=%d\n%s", response.Code, logText)
	}
	if strings.Contains(logText, "oauth-secret") || strings.Contains(logText, "token_hash=") {
		t.Fatalf("failed token audit exposed a secret or hash:\n%s", logText)
	}
}

func TestOAuthUnlinkAuditAndStatusOmission(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fake, github := newFakeGitHub(t, func() time.Time { return now })
	store, err := NewStore(t.TempDir(), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutCredentials("octocat", OAuthCredentials{
		AccessToken:      "base-token",
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	app := testAppWithAudit(t, github, store, func(context.Context, string) (*apitype.WhoIsResponse, error) {
		who := testWhoIs("100", "node-1", testCaps(`{"target":"acme","githubUser":"octocat"}`))
		who.Node.Name = "client.example.ts.net."
		who.UserProfile.LoginName = "alice@example.com"
		return who, nil
	}, func() time.Time { return now }, testAuditLog(&audit))

	status := httptest.NewRecorder()
	app.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github/status", nil))
	if status.Code != http.StatusOK || audit.Len() != 0 {
		t.Fatalf("status request was audited: status=%d\n%s", status.Code, audit.String())
	}
	notFound := httptest.NewRecorder()
	app.ServeHTTP(notFound, httptest.NewRequest(http.MethodGet, "http://tsgh/unknown", nil))
	if notFound.Code != http.StatusNotFound || audit.Len() != 0 {
		t.Fatalf("unknown route was audited: status=%d\n%s", notFound.Code, audit.String())
	}

	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "http://tsgh/auth/github", nil))
	logText := audit.String()
	if response.Code != http.StatusNoContent || strings.Count(logText, "action=oauth.unlink") != 1 || !strings.Contains(logText, "outcome=success") || !strings.Contains(logText, "status=204") || !strings.Contains(logText, "github_actor=octocat") {
		t.Fatalf("unexpected unlink response or audit: status=%d\n%s", response.Code, logText)
	}
	if strings.Contains(logText, "base-token") || strings.Contains(logText, "refresh-token") {
		t.Fatalf("unlink audit exposed credentials:\n%s", logText)
	}
	fake.mu.Lock()
	grantsGone := fake.grantsGone
	fake.mu.Unlock()
	if grantsGone != 1 {
		t.Fatalf("github grants revoked = %d", grantsGone)
	}
}

func TestTaggedNodeOAuthTokenAndRevocation(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	fake, github := newFakeGitHub(t, nowFunc)
	var audit bytes.Buffer
	auditLog := testAuditLog(&audit)
	dir := t.TempDir()
	keyBytes := bytes.Repeat([]byte{9}, 32)
	store, err := NewStore(dir, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	who := func(_ context.Context, remote string) (*apitype.WhoIsResponse, error) {
		nodeID := "node-1"
		if strings.HasPrefix(remote, "other") {
			nodeID = "node-2"
		}
		who := testWhoIs("100", nodeID, testCaps(
			`{"target":"acme","githubUser":"octocat"}`,
			`{"target":"acme","repositories":["api"]}`,
			`{"target":"acme","permissions":{"contents":"read"}}`,
		))
		who.Node.Name = nodeID + ".example.ts.net."
		who.Node.Tags = []string{"tag:ci"}
		who.UserProfile = nil
		return who, nil
	}
	app := testAppWithAudit(t, github, store, who, nowFunc, auditLog)
	notLinked := httptest.NewRecorder()
	app.ServeHTTP(notLinked, httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil))
	if notLinked.Code != http.StatusForbidden || notLinked.Body.String() != "github account \"octocat\" is not linked; visit http://tsgh/auth/github\n" {
		t.Fatalf("not-linked response = %d %q", notLinked.Code, notLinked.Body.String())
	}

	start := httptest.NewRecorder()
	app.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("oauth start = %d %q", start.Code, start.Body.String())
	}
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := location.Query().Get("state")
	if state == "" || location.Query().Get("code_challenge") == "" {
		t.Fatal("oauth redirect omitted state or PKCE challenge")
	}
	verifier := app.pending[state].Verifier
	fake.mu.Lock()
	fake.challenge = location.Query().Get("code_challenge")
	fake.mu.Unlock()

	mismatch := httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github/callback?code=code&state="+url.QueryEscape(state), nil)
	mismatch.RemoteAddr = "other:1234"
	mismatchResponse := httptest.NewRecorder()
	app.ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusForbidden {
		t.Fatalf("identity mismatch = %d", mismatchResponse.Code)
	}

	start = httptest.NewRecorder()
	app.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github", nil))
	location, _ = url.Parse(start.Header().Get("Location"))
	secondState := location.Query().Get("state")
	secondVerifier := app.pending[secondState].Verifier
	fake.mu.Lock()
	fake.challenge = location.Query().Get("code_challenge")
	fake.mu.Unlock()
	callback := httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github/callback?code=code&state="+url.QueryEscape(secondState), nil)
	linked := httptest.NewRecorder()
	app.ServeHTTP(linked, callback)
	if linked.Code != http.StatusOK || linked.Body.String() != "linked octocat\n" {
		t.Fatalf("callback = %d %q", linked.Code, linked.Body.String())
	}
	for range 2 {
		response := httptest.NewRecorder()
		app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil))
		if response.Code != http.StatusOK || response.Body.String() != "user-token-1\n" {
			t.Fatalf("user token = %d %q", response.Code, response.Body.String())
		}
	}
	otherToken := httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil)
	otherToken.RemoteAddr = "other:1234"
	otherResponse := httptest.NewRecorder()
	app.ServeHTTP(otherResponse, otherToken)
	if otherResponse.Code != http.StatusOK || otherResponse.Body.String() != "user-token-2\n" {
		t.Fatalf("other node token response = %d %q", otherResponse.Code, otherResponse.Body.String())
	}
	status := httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github/status", nil)
	status.RemoteAddr = "other:1234"
	statusResponse := httptest.NewRecorder()
	app.ServeHTTP(statusResponse, status)
	if statusResponse.Code != http.StatusOK || statusResponse.Body.String() != "octocat\n" {
		t.Fatalf("other node status response = %d %q", statusResponse.Code, statusResponse.Body.String())
	}
	_, _, scoped, revoked := fake.counts()
	if scoped != 2 || revoked != 0 || len(store.ScopedTokens()) != 2 {
		t.Fatalf("scoped=%d revoked=%d records=%d", scoped, revoked, len(store.ScopedTokens()))
	}
	reloaded, err := NewStore(dir, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	restarted := testAppWithAudit(t, github, reloaded, who, nowFunc, auditLog)
	fake.mu.Lock()
	fake.revokeFail = 1
	fake.mu.Unlock()
	now = now.Add(time.Hour)
	restarted.revokeDue(context.Background())
	if len(reloaded.ScopedTokens()) != 1 {
		t.Fatal("failed revocation was not retained for retry")
	}
	restarted.revokeDue(context.Background())
	_, _, _, revoked = fake.counts()
	if revoked != 3 || len(reloaded.ScopedTokens()) != 0 {
		t.Fatalf("strict revocation failed after restart: attempts=%d records=%d", revoked, len(reloaded.ScopedTokens()))
	}

	logText := audit.String()
	firstSum := sha256.Sum256([]byte("user-token-1"))
	secondSum := sha256.Sum256([]byte("user-token-2"))
	firstHash := base64.StdEncoding.EncodeToString(firstSum[:])
	secondHash := base64.StdEncoding.EncodeToString(secondSum[:])
	for _, field := range []string{
		"action=oauth.authorize_start", "action=oauth.link", "reason=invalid_oauth_callback",
		"reason=github_account_not_linked", "github_actor=octocat", "tailscale_tags=tag:ci",
		"action=token.recover", "action=token.revoke", "reason=github_token_revocation_failed",
		`token_hash="` + firstHash + `"`, `token_hash="` + secondHash + `"`,
	} {
		if !strings.Contains(logText, field) {
			t.Errorf("audit log omitted %q:\n%s", field, logText)
		}
	}
	if strings.Count(logText, "action=oauth.authorize_start") != 2 || strings.Count(logText, "action=oauth.link") != 2 || strings.Count(logText, "action=token.recover") != 2 || strings.Count(logText, "action=token.revoke") != 3 {
		t.Fatalf("unexpected OAuth or token lifecycle audit counts:\n%s", logText)
	}
	for _, secret := range []string{"base-token", "refresh-token", "user-token-", state, secondState, verifier, secondVerifier, "code=code"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("audit log exposed %q:\n%s", secret, logText)
		}
	}
	if strings.Contains(logText, "tailscale_user_login=") {
		t.Fatalf("tagged-node audit unexpectedly included a user login:\n%s", logText)
	}
}

func TestOAuthRefreshIsPersisted(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	fake, github := newFakeGitHub(t, nowFunc)
	dir := t.TempDir()
	keyBytes := bytes.Repeat([]byte{3}, 32)
	store, err := NewStore(dir, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutCredentials("octocat", OAuthCredentials{
		AccessToken:      "old",
		AccessExpiresAt:  now.Add(time.Minute),
		RefreshToken:     "old-refresh",
		RefreshExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	app := testApp(t, github, store, func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
		return testWhoIs("100", "node-1", testCaps(
			`{"target":"acme","githubUser":"octocat"}`,
			`{"target":"acme","repositories":["api"]}`,
			`{"target":"acme","permissions":{"contents":"read"}}`,
		)), nil
	}, nowFunc)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://tsgh/token/acme", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("token response = %d %q", response.Code, response.Body.String())
	}
	fake.mu.Lock()
	refreshed := fake.refreshed
	fake.mu.Unlock()
	if refreshed != 1 {
		t.Fatalf("refresh calls = %d", refreshed)
	}
	reloaded, err := NewStore(dir, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	credentials, ok := reloaded.Credentials("octocat")
	if !ok || credentials.AccessToken != "base-token" || credentials.RefreshToken != "refresh-token" {
		t.Fatalf("rotated credentials not persisted: %#v", credentials)
	}
}

func TestOAuthRefreshPersistenceFailureRevokesReplacement(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fake, github := newFakeGitHub(t, func() time.Time { return now })
	dir := t.TempDir()
	store, err := NewStore(dir, bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	old := OAuthCredentials{
		AccessToken:      "old",
		AccessExpiresAt:  now.Add(time.Minute),
		RefreshToken:     "old-refresh",
		RefreshExpiresAt: now.Add(time.Hour),
	}
	if err := store.PutCredentials("octocat", old); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(dir, "missing", "state.enc")
	app := testApp(t, github, store, func(context.Context, string) (*apitype.WhoIsResponse, error) { return nil, nil }, func() time.Time { return now })
	if _, err := app.credentialsLocked(context.Background(), "octocat"); err == nil {
		t.Fatal("refresh unexpectedly succeeded")
	}
	_, _, _, revoked := fake.counts()
	credentials, _ := store.Credentials("octocat")
	if revoked != 1 || credentials.AccessToken != old.AccessToken {
		t.Fatalf("revoked=%d credentials=%#v", revoked, credentials)
	}
}

func TestUntrackedTokenCleanupIgnoresRequestCancellation(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	var logged string
	github := &GitHub{
		HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			called = true
			if err := request.Context().Err(); err != nil {
				t.Errorf("cleanup context was canceled: %v", err)
			}
			deadline, ok := request.Context().Deadline()
			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 11*time.Second {
				t.Errorf("cleanup context deadline = %v, present=%v", deadline, ok)
			}
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("failure")),
			}, nil
		})},
		APIURL:       "https://github.invalid",
		ClientID:     "client",
		ClientSecret: "secret",
	}
	app, err := NewApp(AppConfig{
		WhoIs:  func(context.Context, string) (*apitype.WhoIsResponse, error) { return nil, nil },
		GitHub: github,
		Logf:   func(format string, _ ...any) { logged = format },
	})
	if err != nil {
		t.Fatal(err)
	}
	app.revokeUntrackedToken(requestCtx, "untracked")
	if !called || logged != "could not revoke untracked user token: %v" {
		t.Fatalf("called=%v log=%q", called, logged)
	}
}

func TestRevokerStopsWithoutShutdownSweep(t *testing.T) {
	now := time.Now()
	store, err := NewStore(t.TempDir(), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddScoped(ScopedToken{
		Token:     "due",
		ExpiresAt: now.Add(time.Hour),
		RevokeAt:  now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	github := &GitHub{
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		APIURL:       "https://github.invalid",
		ClientID:     "client",
		ClientSecret: "secret",
	}
	app := testApp(t, github, store, func(context.Context, string) (*apitype.WhoIsResponse, error) { return nil, nil }, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		app.RunRevoker(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoker did not stop after cancellation")
	}
	if calls != 0 || len(store.ScopedTokens()) != 1 {
		t.Fatalf("shutdown made %d revocation calls and retained %d records", calls, len(store.ScopedTokens()))
	}
}

func testApp(t *testing.T, github *GitHub, store *Store, who WhoIsFunc, now func() time.Time) *App {
	return testAppWithAudit(t, github, store, who, now, nil)
}

func testAppWithAudit(t *testing.T, github *GitHub, store *Store, who WhoIsFunc, now func() time.Time, auditLog *slog.Logger) *App {
	t.Helper()
	app, err := NewApp(AppConfig{
		RedirectURI: "http://tsgh/auth/github/callback",
		WhoIs:       who,
		GitHub:      github,
		Store:       store,
		Now:         now,
		AuditLog:    auditLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func testAuditLog(output io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	}))
}

func testCaps(values ...string) tailcfg.PeerCapMap {
	raw := make([]tailcfg.RawMessage, len(values))
	for i, value := range values {
		raw[i] = tailcfg.RawMessage(value)
	}
	return tailcfg.PeerCapMap{Capability: raw}
}

func testWhoIs(userID, nodeID string, caps tailcfg.PeerCapMap) *apitype.WhoIsResponse {
	var user tailcfg.UserID
	if userID == "200" {
		user = 200
	} else {
		user = 100
	}
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{StableID: tailcfg.StableNodeID(nodeID), Key: key.NewNode().Public()},
		UserProfile: &tailcfg.UserProfile{ID: user},
		CapMap:      caps,
	}
}

func TestGitHubErrorDoesNotExposeBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream secret", http.StatusForbidden)
	}))
	defer server.Close()
	github := &GitHub{HTTP: server.Client(), APIURL: server.URL}
	_, err := github.User(context.Background(), "token")
	if err == nil || strings.Contains(err.Error(), "upstream secret") {
		t.Fatalf("unsafe error: %v", err)
	}
	var githubErr *GitHubError
	if !errors.As(err, &githubErr) || githubErr.Status != http.StatusForbidden {
		t.Fatalf("unexpected error: %v", err)
	}
}
