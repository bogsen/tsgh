package broker

import (
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
	"net/url"
	"strconv"
	"strings"
	"time"
)

const githubAPIVersion = "2026-03-10"

type GitHub struct {
	HTTP         *http.Client
	APIURL       string
	WebURL       string
	AppID        int64
	ClientID     string
	ClientSecret string
	PrivateKey   *rsa.PrivateKey
	Now          func() time.Time
}

type GitHubError struct {
	Status int
	Op     string
}

func (e *GitHubError) Error() string {
	return fmt.Sprintf("github %s returned HTTP %d", e.Op, e.Status)
}

type OAuthCredentials struct {
	AccessToken      string    `json:"accessToken"`
	AccessExpiresAt  time.Time `json:"accessExpiresAt"`
	RefreshToken     string    `json:"refreshToken"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt"`
}

type GitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type IssuedToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (g *GitHub) defaults() {
	if g.HTTP == nil {
		g.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if g.APIURL == "" {
		g.APIURL = "https://api.github.com"
	}
	if g.WebURL == "" {
		g.WebURL = "https://github.com"
	}
	if g.Now == nil {
		g.Now = time.Now
	}
}

func (g *GitHub) AuthorizationURL(state, challenge, redirectURI string) string {
	g.defaults()
	values := url.Values{
		"client_id":             {g.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return strings.TrimRight(g.WebURL, "/") + "/login/oauth/authorize?" + values.Encode()
}

func (g *GitHub) ExchangeCode(ctx context.Context, code, verifier, redirectURI string) (OAuthCredentials, error) {
	return g.oauthToken(ctx, url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	})
}

func (g *GitHub) Refresh(ctx context.Context, refreshToken string) (OAuthCredentials, error) {
	return g.oauthToken(ctx, url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func (g *GitHub) oauthToken(ctx context.Context, values url.Values) (OAuthCredentials, error) {
	g.defaults()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(g.WebURL, "/")+"/login/oauth/access_token", strings.NewReader(values.Encode()))
	if err != nil {
		return OAuthCredentials{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		AccessToken           string `json:"access_token"`
		ExpiresIn             int64  `json:"expires_in"`
		RefreshToken          string `json:"refresh_token"`
		RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
		Error                 string `json:"error"`
	}
	if err := g.do(req, "oauth token", &response, http.StatusOK); err != nil {
		return OAuthCredentials{}, err
	}
	if response.Error != "" || response.AccessToken == "" {
		return OAuthCredentials{}, errors.New("github rejected oauth token exchange")
	}
	now := g.Now()
	return OAuthCredentials{
		AccessToken:      response.AccessToken,
		AccessExpiresAt:  now.Add(time.Duration(response.ExpiresIn) * time.Second),
		RefreshToken:     response.RefreshToken,
		RefreshExpiresAt: now.Add(time.Duration(response.RefreshTokenExpiresIn) * time.Second),
	}, nil
}

func (g *GitHub) User(ctx context.Context, token string) (GitHubUser, error) {
	var user GitHubUser
	if err := g.api(ctx, http.MethodGet, "/user", token, nil, &user, http.StatusOK); err != nil {
		return GitHubUser{}, err
	}
	if user.ID == 0 || user.Login == "" {
		return GitHubUser{}, errors.New("github returned an invalid user")
	}
	return user, nil
}

func (g *GitHub) ResolveInstallation(ctx context.Context, target string) (int64, error) {
	jwt, err := g.appJWT()
	if err != nil {
		return 0, err
	}
	for _, path := range []string{"/orgs/" + url.PathEscape(target) + "/installation", "/users/" + url.PathEscape(target) + "/installation"} {
		var installation struct {
			ID int64 `json:"id"`
		}
		err := g.api(ctx, http.MethodGet, path, jwt, nil, &installation, http.StatusOK)
		if err == nil {
			if installation.ID == 0 {
				return 0, errors.New("github returned an invalid installation")
			}
			return installation.ID, nil
		}
		var githubErr *GitHubError
		if !errors.As(err, &githubErr) || githubErr.Status != http.StatusNotFound {
			return 0, err
		}
	}
	return 0, &GitHubError{Status: http.StatusNotFound, Op: "resolve installation"}
}

func (g *GitHub) CreateInstallationToken(ctx context.Context, installationID int64, scope Scope) (IssuedToken, error) {
	jwt, err := g.appJWT()
	if err != nil {
		return IssuedToken{}, err
	}
	body := struct {
		Repositories []string          `json:"repositories,omitempty"`
		Permissions  map[string]string `json:"permissions"`
	}{scope.githubRepositories(), scope.Permissions}
	var token IssuedToken
	path := "/app/installations/" + strconv.FormatInt(installationID, 10) + "/access_tokens"
	if err := g.api(ctx, http.MethodPost, path, jwt, body, &token, http.StatusCreated); err != nil {
		return IssuedToken{}, err
	}
	return validateIssuedToken(token)
}

func (g *GitHub) CreateScopedUserToken(ctx context.Context, baseToken string, scope Scope) (IssuedToken, error) {
	body := struct {
		AccessToken  string            `json:"access_token"`
		Target       string            `json:"target"`
		Repositories []string          `json:"repositories,omitempty"`
		Permissions  map[string]string `json:"permissions"`
	}{baseToken, scope.Target, scope.githubRepositories(), scope.Permissions}
	var token IssuedToken
	path := "/applications/" + url.PathEscape(g.ClientID) + "/token/scoped"
	if err := g.apiBasic(ctx, http.MethodPost, path, body, &token, http.StatusOK); err != nil {
		return IssuedToken{}, err
	}
	return validateIssuedToken(token)
}

func validateIssuedToken(token IssuedToken) (IssuedToken, error) {
	if token.Token == "" || token.ExpiresAt.IsZero() {
		return IssuedToken{}, errors.New("github returned an invalid token")
	}
	return token, nil
}

func (g *GitHub) RevokeUserToken(ctx context.Context, token string) error {
	body := struct {
		AccessToken string `json:"access_token"`
	}{token}
	return g.apiBasic(ctx, http.MethodDelete, "/applications/"+url.PathEscape(g.ClientID)+"/token", body, nil, http.StatusNoContent)
}

func (g *GitHub) RevokeAuthorization(ctx context.Context, token string) error {
	body := struct {
		AccessToken string `json:"access_token"`
	}{token}
	return g.apiBasic(ctx, http.MethodDelete, "/applications/"+url.PathEscape(g.ClientID)+"/grant", body, nil, http.StatusNoContent)
}

func (g *GitHub) api(ctx context.Context, method, path, token string, body, out any, status int) error {
	return g.request(ctx, method, path, token, false, body, out, status)
}

func (g *GitHub) apiBasic(ctx context.Context, method, path string, body, out any, status int) error {
	return g.request(ctx, method, path, "", true, body, out, status)
}

func (g *GitHub) request(ctx context.Context, method, path, token string, basic bool, body, out any, status int) error {
	g.defaults()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.APIURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if basic {
		req.SetBasicAuth(g.ClientID, g.ClientSecret)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", "tsgh")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return g.do(req, path, out, status)
}

func (g *GitHub) do(req *http.Request, op string, out any, expected int) error {
	response, err := g.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("github %s: %w", op, err)
	}
	defer response.Body.Close()
	if response.StatusCode != expected {
		io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return &GitHubError{Status: response.StatusCode, Op: op}
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode github %s response: %w", op, err)
	}
	return nil
}

func (g *GitHub) appJWT() (string, error) {
	g.defaults()
	if g.PrivateKey == nil || g.AppID == 0 {
		return "", errors.New("github app credentials are not configured")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(map[string]any{
		"iat": g.Now().Add(-time.Minute).Unix(),
		"exp": g.Now().Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(g.AppID, 10),
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, g.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
