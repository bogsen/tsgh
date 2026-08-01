package broker

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Hostname string
	StateDir string
	GitHub   *GitHub
	Store    *Store
}

func LoadConfig() (Config, error) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return Config{}, errors.New("determine system hostname")
	}
	appIDText := os.Getenv("TSGH_GITHUB_APP_ID")
	privateKeyFile := os.Getenv("TSGH_GITHUB_PRIVATE_KEY_FILE")
	stateDir := os.Getenv("TSGH_STATE_DIR")
	if appIDText == "" || privateKeyFile == "" || stateDir == "" {
		return Config{}, errors.New("TSGH_GITHUB_APP_ID, TSGH_GITHUB_PRIVATE_KEY_FILE, and TSGH_STATE_DIR are required")
	}
	appID, err := strconv.ParseInt(appIDText, 10, 64)
	if err != nil || appID <= 0 {
		return Config{}, errors.New("TSGH_GITHUB_APP_ID must be a positive integer")
	}
	privateKey, err := readPrivateKey(privateKeyFile)
	if err != nil {
		return Config{}, fmt.Errorf("github private key: %w", err)
	}
	config := Config{
		Hostname: hostname,
		StateDir: stateDir,
		GitHub:   &GitHub{AppID: appID, PrivateKey: privateKey},
	}

	clientID := os.Getenv("TSGH_GITHUB_CLIENT_ID")
	clientSecretFile := os.Getenv("TSGH_GITHUB_CLIENT_SECRET_FILE")
	storeKeyFile := os.Getenv("TSGH_STORE_KEY_FILE")
	userTokensEnabled := clientID != "" || clientSecretFile != "" || storeKeyFile != ""
	if !userTokensEnabled {
		return config, nil
	}
	if clientID == "" || clientSecretFile == "" || storeKeyFile == "" {
		return Config{}, errors.New("user token support requires TSGH_GITHUB_CLIENT_ID, TSGH_GITHUB_CLIENT_SECRET_FILE, and TSGH_STORE_KEY_FILE")
	}
	clientSecret, err := readTrimmed(clientSecretFile)
	if err != nil {
		return Config{}, fmt.Errorf("github client secret: %w", err)
	}
	key, err := ReadStoreKey(storeKeyFile)
	if err != nil {
		return Config{}, fmt.Errorf("state key: %w", err)
	}
	store, err := NewStore(config.StateDir, key)
	if err != nil {
		return Config{}, fmt.Errorf("state store: %w", err)
	}
	config.GitHub.ClientID = clientID
	config.GitHub.ClientSecret = clientSecret
	config.Store = store
	return config, nil
}

func (c Config) TSNetDir() string {
	return filepath.Join(c.StateDir, "tsnet")
}

func readTrimmed(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return "", errors.New("secret file is empty")
	}
	return trimmed, nil
}

func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key must be PKCS#1 or PKCS#8 RSA PEM")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}
