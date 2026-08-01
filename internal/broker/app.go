package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

type WhoIsFunc func(context.Context, string) (*apitype.WhoIsResponse, error)

type AppConfig struct {
	RedirectURI string
	WhoIs       WhoIsFunc
	GitHub      *GitHub
	Store       *Store
	Now         func() time.Time
	Logf        func(string, ...any)
}

type caller struct {
	NodeID string
	WhoIs  *apitype.WhoIsResponse
}

type pendingOAuth struct {
	NodeID   string
	Verifier string
	Expires  time.Time
}

type cachedInstallationToken struct {
	Token     string
	ExpiresAt time.Time
}

type App struct {
	redirectURI string
	whoIs       WhoIsFunc
	github      *GitHub
	store       *Store
	now         func() time.Time
	logf        func(string, ...any)

	// ponytail: one lock keeps refresh-token rotation and tiny caches correct;
	// split it per user only if request throughput ever makes this measurable.
	mu                 sync.Mutex
	pending            map[string]pendingOAuth
	installationIDs    map[string]int64
	installationTokens map[string]cachedInstallationToken
	revokerWake        chan struct{}
}

func NewApp(config AppConfig) (*App, error) {
	if config.WhoIs == nil || config.GitHub == nil {
		return nil, errors.New("WhoIs and GitHub are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.GitHub.Now == nil {
		config.GitHub.Now = config.Now
	}
	config.GitHub.defaults()
	if config.Logf == nil {
		config.Logf = func(string, ...any) {}
	}
	return &App{
		redirectURI:        config.RedirectURI,
		whoIs:              config.WhoIs,
		github:             config.GitHub,
		store:              config.Store,
		now:                config.Now,
		logf:               config.Logf,
		pending:            map[string]pendingOAuth{},
		installationIDs:    map[string]int64{},
		installationTokens: map[string]cachedInstallationToken{},
		revokerWake:        make(chan struct{}, 1),
	}, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	identity, err := a.authenticate(r)
	if err != nil {
		http.Error(w, "tailscale identity required", http.StatusUnauthorized)
		return
	}

	switch {
	case strings.HasPrefix(r.URL.Path, "/token/") && strings.TrimPrefix(r.URL.Path, "/token/") != "" && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/token/"), "/"):
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleToken(w, r, identity, strings.TrimPrefix(r.URL.Path, "/token/"))
	case r.URL.Path == "/auth/github":
		if r.Method == http.MethodGet {
			a.handleOAuthStart(w, r, identity)
		} else if r.Method == http.MethodDelete {
			a.handleOAuthDelete(w, r, identity)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case r.URL.Path == "/auth/github/callback":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleOAuthCallback(w, r, identity)
	case r.URL.Path == "/auth/github/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleOAuthStatus(w, r, identity)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (a *App) authenticate(r *http.Request) (caller, error) {
	who, err := a.whoIs(r.Context(), r.RemoteAddr)
	if err != nil || who == nil || who.Node == nil {
		return caller{}, errors.New("whois failed")
	}
	nodeID := string(who.Node.StableID)
	if nodeID == "" {
		nodeID = who.Node.Key.String()
	}
	return caller{
		NodeID: nodeID,
		WhoIs:  who,
	}, nil
}

func (a *App) handleToken(w http.ResponseWriter, r *http.Request, identity caller, target string) {
	scope, err := ScopeFromCaps(identity.WhoIs.CapMap, target)
	if err != nil {
		http.Error(w, "token is not granted", http.StatusForbidden)
		return
	}
	token, err := a.issueToken(r.Context(), identity, scope)
	if err != nil {
		var response *responseError
		if errors.As(err, &response) {
			if response.err != nil {
				a.logf("token request failed for target %q: %v", target, response.err)
			}
			http.Error(w, response.message, response.status)
			return
		}
		var githubErr *GitHubError
		if errors.As(err, &githubErr) && githubErr.Status == http.StatusNotFound && githubErr.Op == "resolve installation" {
			a.logf("token request failed for target %q: %v", target, err)
			http.Error(w, fmt.Sprintf("github app is not installed for target %q", target), http.StatusNotFound)
			return
		}
		a.logf("token request failed for target %q: %v", target, err)
		http.Error(w, "github token request failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, token)
}

type responseError struct {
	status  int
	message string
	err     error
}

func (e *responseError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.message
}

func (e *responseError) Unwrap() error { return e.err }

func (a *App) issueToken(ctx context.Context, identity caller, scope Scope) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if scope.GitHubUser != "" {
		return a.issueUserTokenLocked(ctx, identity, scope)
	}
	return a.issueInstallationTokenLocked(ctx, scope)
}

func (a *App) issueUserTokenLocked(ctx context.Context, identity caller, scope Scope) (string, error) {
	if a.store == nil || a.github.ClientID == "" || a.github.ClientSecret == "" {
		return "", &responseError{status: http.StatusServiceUnavailable, message: "user token support is not configured"}
	}
	credentials, err := a.credentialsLocked(ctx, scope.GitHubUser)
	if err != nil {
		return "", err
	}
	user, err := a.github.User(ctx, credentials.AccessToken)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(user.Login, scope.GitHubUser) {
		return "", &responseError{status: http.StatusForbidden, message: "linked github user does not match grant"}
	}
	if token, ok := a.store.MatchingScoped(identity.NodeID, scope.Target, user.Login, scope.Key(), a.now()); ok {
		return token.Token, nil
	}
	issued, err := a.github.CreateScopedUserToken(ctx, credentials.AccessToken, scope)
	if err != nil {
		return "", err
	}
	revokeAt := a.now().Add(time.Hour)
	if issued.ExpiresAt.Before(revokeAt) {
		revokeAt = issued.ExpiresAt
	}
	if !revokeAt.After(a.now()) {
		return "", errors.New("github returned an expired token")
	}
	record := ScopedToken{
		Token:     issued.Token,
		NodeID:    identity.NodeID,
		Target:    scope.Target,
		Actor:     user.Login,
		ScopeKey:  scope.Key(),
		ExpiresAt: issued.ExpiresAt,
		RevokeAt:  revokeAt,
	}
	if err := a.store.AddScoped(record); err != nil {
		a.revokeUntrackedToken(ctx, issued.Token)
		return "", &responseError{
			status:  http.StatusInternalServerError,
			message: "token state operation failed",
			err:     fmt.Errorf("persist scoped token: %w", err),
		}
	}
	select {
	case a.revokerWake <- struct{}{}:
	default:
	}
	return issued.Token, nil
}

func (a *App) credentialsLocked(ctx context.Context, login string) (OAuthCredentials, error) {
	credentials, ok := a.store.Credentials(login)
	if !ok {
		return OAuthCredentials{}, &responseError{
			status:  http.StatusForbidden,
			message: fmt.Sprintf("github account %q is not linked; visit %s", login, a.githubLinkURL()),
		}
	}
	if credentials.AccessExpiresAt.After(a.now().Add(5 * time.Minute)) {
		return credentials, nil
	}
	if credentials.RefreshToken == "" || !credentials.RefreshExpiresAt.After(a.now()) {
		return OAuthCredentials{}, &responseError{
			status:  http.StatusForbidden,
			message: fmt.Sprintf("github authorization for %q must be renewed; visit %s", login, a.githubLinkURL()),
		}
	}
	refreshed, err := a.github.Refresh(ctx, credentials.RefreshToken)
	if err != nil {
		return OAuthCredentials{}, err
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshExpiresAt.IsZero() {
		return OAuthCredentials{}, errors.New("github app must enable expiring user tokens")
	}
	if err := a.store.PutCredentials(login, refreshed); err != nil {
		a.revokeUntrackedToken(ctx, refreshed.AccessToken)
		return OAuthCredentials{}, &responseError{
			status:  http.StatusInternalServerError,
			message: "token state operation failed",
			err:     fmt.Errorf("persist refreshed oauth credentials: %w", err),
		}
	}
	return refreshed, nil
}

func (a *App) issueInstallationTokenLocked(ctx context.Context, scope Scope) (string, error) {
	cacheKey := strings.ToLower(scope.Target) + ":" + scope.Key()
	if token, ok := a.installationTokens[cacheKey]; ok && token.ExpiresAt.After(a.now().Add(time.Minute)) {
		return token.Token, nil
	}
	targetKey := strings.ToLower(scope.Target)
	installationID := a.installationIDs[targetKey]
	if installationID == 0 {
		var err error
		installationID, err = a.github.ResolveInstallation(ctx, scope.Target)
		if err != nil {
			return "", err
		}
		a.installationIDs[targetKey] = installationID
	}
	issued, err := a.github.CreateInstallationToken(ctx, installationID, scope)
	var githubErr *GitHubError
	if errors.As(err, &githubErr) && githubErr.Status == http.StatusNotFound {
		delete(a.installationIDs, targetKey)
		installationID, err = a.github.ResolveInstallation(ctx, scope.Target)
		if err == nil {
			a.installationIDs[targetKey] = installationID
			issued, err = a.github.CreateInstallationToken(ctx, installationID, scope)
		}
	}
	if err != nil {
		return "", err
	}
	a.installationTokens[cacheKey] = cachedInstallationToken{issued.Token, issued.ExpiresAt}
	return issued.Token, nil
}

func (a *App) handleOAuthStart(w http.ResponseWriter, r *http.Request, identity caller) {
	if !a.userTokensEnabled() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	state, err := randomString(32)
	if err != nil {
		http.Error(w, "could not start authorization", http.StatusInternalServerError)
		return
	}
	verifier, err := randomString(48)
	if err != nil {
		http.Error(w, "could not start authorization", http.StatusInternalServerError)
		return
	}
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	a.mu.Lock()
	a.pending[state] = pendingOAuth{identity.NodeID, verifier, a.now().Add(5 * time.Minute)}
	for key, pending := range a.pending {
		if !pending.Expires.After(a.now()) {
			delete(a.pending, key)
		}
	}
	a.mu.Unlock()
	http.Redirect(w, r, a.github.AuthorizationURL(state, challenge, a.redirectURI), http.StatusFound)
}

func (a *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request, identity caller) {
	if !a.userTokensEnabled() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "github authorization was denied", http.StatusForbidden)
		return
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	a.mu.Lock()
	pending, ok := a.pending[state]
	delete(a.pending, state)
	a.mu.Unlock()
	if !ok || code == "" || pending.NodeID != identity.NodeID || !pending.Expires.After(a.now()) {
		http.Error(w, "invalid oauth callback", http.StatusForbidden)
		return
	}
	credentials, err := a.github.ExchangeCode(r.Context(), code, pending.Verifier, a.redirectURI)
	if err != nil {
		a.logf("github oauth exchange failed: %v", err)
		http.Error(w, "github authorization failed", http.StatusBadGateway)
		return
	}
	if credentials.RefreshToken == "" || credentials.RefreshExpiresAt.IsZero() {
		a.revokeUntrackedToken(r.Context(), credentials.AccessToken)
		http.Error(w, "github app must enable expiring user tokens", http.StatusBadGateway)
		return
	}
	user, err := a.github.User(r.Context(), credentials.AccessToken)
	if err != nil {
		a.revokeUntrackedToken(r.Context(), credentials.AccessToken)
		http.Error(w, "github identity lookup failed", http.StatusBadGateway)
		return
	}
	granted, err := HasGitHubUser(identity.WhoIs.CapMap, user.Login)
	if err != nil || !granted {
		a.revokeUntrackedToken(r.Context(), credentials.AccessToken)
		http.Error(w, "github user is not granted", http.StatusForbidden)
		return
	}
	if err := a.store.PutCredentials(user.Login, credentials); err != nil {
		a.revokeUntrackedToken(r.Context(), credentials.AccessToken)
		http.Error(w, "could not persist authorization", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "linked %s\n", user.Login)
}

func (a *App) handleOAuthStatus(w http.ResponseWriter, r *http.Request, identity caller) {
	if !a.userTokensEnabled() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	users, err := GitHubUsers(identity.WhoIs.CapMap)
	if err != nil {
		http.Error(w, "github user grant is invalid", http.StatusForbidden)
		return
	}
	linked := make([]string, 0, len(users))
	for _, login := range users {
		a.mu.Lock()
		credentials, err := a.credentialsLocked(r.Context(), login)
		a.mu.Unlock()
		var response *responseError
		if errors.As(err, &response) && response.status == http.StatusForbidden {
			continue
		}
		if err != nil {
			http.Error(w, "github identity lookup failed", http.StatusBadGateway)
			return
		}
		user, err := a.github.User(r.Context(), credentials.AccessToken)
		if err != nil {
			http.Error(w, "github identity lookup failed", http.StatusBadGateway)
			return
		}
		if strings.EqualFold(user.Login, login) {
			linked = append(linked, user.Login)
		}
	}
	if len(linked) == 0 {
		http.Error(w, "github account is not linked; visit "+a.githubLinkURL(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, login := range linked {
		fmt.Fprintln(w, login)
	}
}

func (a *App) handleOAuthDelete(w http.ResponseWriter, r *http.Request, identity caller) {
	if !a.userTokensEnabled() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	users, err := GitHubUsers(identity.WhoIs.CapMap)
	if err != nil {
		http.Error(w, "github user grant is invalid", http.StatusForbidden)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	deleted := false
	for _, login := range users {
		credentials, ok := a.store.Credentials(login)
		if !ok {
			continue
		}
		if err := a.github.RevokeAuthorization(r.Context(), credentials.AccessToken); err != nil {
			var githubErr *GitHubError
			if !errors.As(err, &githubErr) || githubErr.Status != http.StatusNotFound {
				http.Error(w, "github authorization revocation failed", http.StatusBadGateway)
				return
			}
		}
		if err := a.store.DeleteGitHubUser(login); err != nil {
			http.Error(w, "could not remove authorization", http.StatusInternalServerError)
			return
		}
		deleted = true
	}
	if !deleted {
		http.Error(w, "github account is not linked", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) userTokensEnabled() bool {
	return a.store != nil && a.redirectURI != "" && a.github.ClientID != "" && a.github.ClientSecret != ""
}

func (a *App) githubLinkURL() string { return strings.TrimSuffix(a.redirectURI, "/callback") }

func randomString(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (a *App) revokeUntrackedToken(requestCtx context.Context, token string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(requestCtx), 10*time.Second)
	defer cancel()
	if err := a.github.RevokeUserToken(ctx, token); err != nil {
		a.logf("could not revoke untracked user token: %v", err)
	}
}

func (a *App) RunRevoker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		wait := a.revokeDue(ctx)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-a.revokerWake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (a *App) revokeDue(ctx context.Context) time.Duration {
	if a.store == nil {
		return time.Hour
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	wait := time.Hour
	for _, token := range a.store.ScopedTokens() {
		if !token.ExpiresAt.After(a.now()) {
			if err := a.store.RemoveScoped(token.Token); err != nil {
				a.logf("could not discard expired scoped token record: %v", err)
			}
			continue
		}
		if token.RevokeAt.After(a.now()) {
			if until := token.RevokeAt.Sub(a.now()); until < wait {
				wait = until
			}
			continue
		}
		err := a.github.RevokeUserToken(ctx, token.Token)
		var githubErr *GitHubError
		if err != nil && (!errors.As(err, &githubErr) || githubErr.Status != http.StatusNotFound) {
			a.logf("scoped user token revocation failed; will retry: %v", err)
			wait = min(wait, 30*time.Second)
			continue
		}
		if err := a.store.RemoveScoped(token.Token); err != nil {
			a.logf("could not remove revoked scoped token record: %v", err)
		}
	}
	return wait
}
