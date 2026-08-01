package broker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const stateMagic = "TSGH1\n"

type ScopedToken struct {
	Token     string    `json:"token"`
	NodeID    string    `json:"nodeID"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	ScopeKey  string    `json:"scopeKey"`
	ExpiresAt time.Time `json:"expiresAt"`
	RevokeAt  time.Time `json:"revokeAt"`
}

type diskState struct {
	Users  map[string]OAuthCredentials `json:"users,omitempty"`
	Scoped []ScopedToken               `json:"scoped,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	aead  cipher.AEAD
	state diskState
}

func ReadStoreKey(path string) ([]byte, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(value) == 32 {
		return value, nil
	}
	if len(value) == 33 && value[32] == '\n' {
		return value[:32], nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(value)))
	if decodeErr != nil || len(decoded) != 32 {
		return nil, errors.New("store key must be 32 raw bytes or base64-encoded 32 bytes")
	}
	return decoded, nil
}

func NewStore(dir string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{
		path:  filepath.Join(dir, "state.enc"),
		aead:  aead,
		state: diskState{Users: map[string]OAuthCredentials{}},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) < len(stateMagic)+s.aead.NonceSize() || string(data[:len(stateMagic)]) != stateMagic {
		return errors.New("invalid encrypted state file")
	}
	nonce := data[len(stateMagic) : len(stateMagic)+s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, data[len(stateMagic)+s.aead.NonceSize():], []byte(stateMagic))
	if err != nil {
		return fmt.Errorf("decrypt state: %w", err)
	}
	if err := json.Unmarshal(plaintext, &s.state); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if s.state.Users == nil {
		s.state.Users = map[string]OAuthCredentials{}
	}
	return nil
}

func (s *Store) save(state diskState) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	data := append([]byte(stateMagic), nonce...)
	data = s.aead.Seal(data, nonce, plaintext, []byte(stateMagic))
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	return directory.Sync()
}

func (s *Store) Credentials(login string) (OAuthCredentials, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credentials, ok := s.state.Users[strings.ToLower(login)]
	return credentials, ok
}

func (s *Store) PutCredentials(login string, credentials OAuthCredentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	next.Users[strings.ToLower(login)] = credentials
	if err := s.save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) DeleteGitHubUser(login string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	delete(next.Users, strings.ToLower(login))
	next.Scoped = next.Scoped[:0]
	for _, token := range s.state.Scoped {
		if !strings.EqualFold(token.Actor, login) {
			next.Scoped = append(next.Scoped, token)
		}
	}
	if err := s.save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) MatchingScoped(nodeID, target, actor, scopeKey string, now time.Time) (ScopedToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	minimum := now.Add(30 * time.Second)
	for _, token := range s.state.Scoped {
		if token.NodeID == nodeID && strings.EqualFold(token.Target, target) && strings.EqualFold(token.Actor, actor) && token.ScopeKey == scopeKey && token.RevokeAt.After(minimum) && token.ExpiresAt.After(minimum) {
			return token, true
		}
	}
	return ScopedToken{}, false
}

func (s *Store) AddScoped(token ScopedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	next.Scoped = append(next.Scoped, token)
	if err := s.save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) ScopedTokens() []ScopedToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ScopedToken(nil), s.state.Scoped...)
}

func (s *Store) RemoveScoped(value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	next.Scoped = next.Scoped[:0]
	for _, token := range s.state.Scoped {
		if token.Token != value {
			next.Scoped = append(next.Scoped, token)
		}
	}
	if len(next.Scoped) == len(s.state.Scoped) {
		return nil
	}
	if err := s.save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func cloneState(state diskState) diskState {
	return diskState{Users: maps.Clone(state.Users), Scoped: slices.Clone(state.Scoped)}
}
