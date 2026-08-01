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
		json.NewEncoder(w).Encode(IssuedToken{Token: "installation-token", ExpiresAt: f.now().Add(time.Hour)})
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
	app := testApp(t, github, nil, func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
		return testWhoIs("100", "node-1", testCaps(
			`{"target":"acme","repositories":["api"]}`,
			`{"target":"acme","permissions":{"contents":"read"}}`,
		)), nil
	}, func() time.Time { return now })

	for _, scheme := range []string{"http", "https"} {
		req := httptest.NewRequest(http.MethodPost, scheme+"://tsgh/token/acme", nil)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		if response.Code != http.StatusOK || response.Body.String() != "installation-token\n" {
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

func TestTaggedNodeOAuthTokenAndRevocation(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return now }
	fake, github := newFakeGitHub(t, nowFunc)
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
		who.Node.Tags = []string{"tag:ci"}
		who.UserProfile = nil
		return who, nil
	}
	app := testApp(t, github, store, who, nowFunc)
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
	fake.mu.Lock()
	fake.challenge = location.Query().Get("code_challenge")
	fake.mu.Unlock()
	callback := httptest.NewRequest(http.MethodGet, "http://tsgh/auth/github/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
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
	restarted := testApp(t, github, reloaded, who, nowFunc)
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
	t.Helper()
	app, err := NewApp(AppConfig{
		RedirectURI: "http://tsgh/auth/github/callback",
		WhoIs:       who,
		GitHub:      github,
		Store:       store,
		Now:         now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return app
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
