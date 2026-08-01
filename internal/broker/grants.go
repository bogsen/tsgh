package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"tailscale.com/tailcfg"
)

const Capability = "bog.dev/cap/github"

type grantValue struct {
	Target       string            `json:"target"`
	GitHubUser   string            `json:"githubUser,omitempty"`
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

// Scope is the normalized GitHub scope granted to one request.
type Scope struct {
	Target       string
	GitHubUser   string
	Repositories []string
	Permissions  map[string]string
}

func ScopeFromCaps(caps tailcfg.PeerCapMap, target string) (Scope, error) {
	if target == "" {
		return Scope{}, errors.New("target is required")
	}
	raw, ok := caps[Capability]
	if !ok {
		return Scope{}, errors.New("capability is not granted")
	}

	scope := Scope{Target: target, Permissions: map[string]string{}}
	repositories := map[string]string{}
	hasRepositories, hasPermissions := false, false
	for _, message := range raw {
		value, err := decodeGrantValue(message)
		if err != nil {
			return Scope{}, err
		}
		if !strings.EqualFold(value.Target, target) {
			continue
		}
		switch {
		case value.GitHubUser != "":
			if scope.GitHubUser != "" && !strings.EqualFold(scope.GitHubUser, value.GitHubUser) {
				return Scope{}, errors.New("conflicting githubUser values")
			}
			scope.GitHubUser = value.GitHubUser
		case value.Repositories != nil:
			hasRepositories = true
			for _, repository := range value.Repositories {
				key := strings.ToLower(repository)
				repositories[key] = repository
			}
		case value.Permissions != nil:
			hasPermissions = true
			for permission, level := range value.Permissions {
				if permissionRank(level) > permissionRank(scope.Permissions[permission]) {
					scope.Permissions[permission] = level
				}
			}
		}
	}
	if !hasRepositories || !hasPermissions {
		return Scope{}, errors.New("target requires separate repositories and permissions grants")
	}
	if len(repositories) == 0 || len(scope.Permissions) == 0 {
		return Scope{}, errors.New("repositories and permissions must not be empty")
	}
	if wildcard, ok := repositories["*"]; ok {
		scope.Repositories = []string{wildcard}
	} else {
		for _, repository := range repositories {
			scope.Repositories = append(scope.Repositories, repository)
		}
		slices.SortFunc(scope.Repositories, func(a, b string) int {
			return strings.Compare(strings.ToLower(a), strings.ToLower(b))
		})
	}
	return scope, nil
}

func decodeGrantValue(raw tailcfg.RawMessage) (grantValue, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value grantValue
	if err := decoder.Decode(&value); err != nil {
		return grantValue{}, fmt.Errorf("invalid capability value: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return grantValue{}, errors.New("invalid capability value: trailing JSON")
	}
	if value.Target == "" || strings.TrimSpace(value.Target) != value.Target {
		return grantValue{}, errors.New("capability target must be non-empty and trimmed")
	}
	kinds := 0
	if value.GitHubUser != "" {
		kinds++
		if strings.TrimSpace(value.GitHubUser) != value.GitHubUser {
			return grantValue{}, errors.New("githubUser must be trimmed")
		}
	}
	if value.Repositories != nil {
		kinds++
		for _, repository := range value.Repositories {
			if repository == "" || strings.TrimSpace(repository) != repository || strings.Contains(repository, "/") {
				return grantValue{}, fmt.Errorf("invalid repository %q", repository)
			}
		}
	}
	if value.Permissions != nil {
		kinds++
		for permission, level := range value.Permissions {
			if permission == "" || strings.TrimSpace(permission) != permission || permissionRank(level) == 0 {
				return grantValue{}, fmt.Errorf("invalid permission %q=%q", permission, level)
			}
		}
	}
	if kinds != 1 {
		return grantValue{}, errors.New("capability value must contain exactly one of githubUser, repositories, or permissions")
	}
	return value, nil
}

func permissionRank(level string) int {
	switch level {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	default:
		return 0
	}
}

func HasGitHubUser(caps tailcfg.PeerCapMap, login string) (bool, error) {
	users, err := GitHubUsers(caps)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(users, func(user string) bool {
		return strings.EqualFold(user, login)
	}), nil
}

func GitHubUsers(caps tailcfg.PeerCapMap) ([]string, error) {
	users := map[string]string{}
	for _, raw := range caps[Capability] {
		value, err := decodeGrantValue(raw)
		if err != nil {
			return nil, err
		}
		if value.GitHubUser != "" {
			users[strings.ToLower(value.GitHubUser)] = value.GitHubUser
		}
	}
	result := make([]string, 0, len(users))
	for _, user := range users {
		result = append(result, user)
	}
	slices.SortFunc(result, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return result, nil
}

func (s Scope) Key() string {
	permissions := make([]string, 0, len(s.Permissions))
	for permission, level := range s.Permissions {
		permissions = append(permissions, permission+"="+level)
	}
	slices.Sort(permissions)
	repositories := make([]string, len(s.Repositories))
	for i, repository := range s.Repositories {
		repositories[i] = strings.ToLower(repository)
	}
	value := strings.ToLower(s.Target) + "\n" + strings.ToLower(s.GitHubUser) + "\n" + strings.Join(repositories, "\n") + "\n" + strings.Join(permissions, "\n")
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s Scope) githubRepositories() []string {
	if len(s.Repositories) == 1 && s.Repositories[0] == "*" {
		return nil
	}
	return s.Repositories
}
