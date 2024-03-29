package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	defMaxUploadSize = 1024 * 1024 // 1MB
	defPort          = "8080"

	maxUploadSizeEnv = "MATCHER_MAX_UPLOAD_SIZE"
	portEnv          = "MATCHER_PORT"
	secretEnv        = "MATCHER_SECRET"
	secretLengthEnv  = "MATCHER_SECRET_LENGTH"
	domainsEnv       = "MATCHER_DOMAINS"
	certFileEnv      = "MATCHER_CERT"
	keyFileEnv       = "MATCHER_KEY"

	oauth2ClientIDEnv     = "MATCHER_CLIENTID"
	oauth2ClientSecretEnv = "MATCHER_CLIENTSECRET"
	oauth2RedirectURLEnv  = "MATCHER_REDIRECTURL"

	cookieStoreKeyEnv = "MATCHER_COOKIESTOREKEY"

	defSecretLength = 16
)

type Config struct {
	AllowedDomains []string
	MaxUploadSize  int64
	Port           string
	Secret         string
	CertFile       string
	KeyFile        string
	OAuth2Config   *oauth2.Config
	CookieStoreKey string
}

func FromEnv() (*Config, error) {
	cfg := &Config{
		Port: defPort,
	}

	var err error

	cfg.Secret = os.Getenv(secretEnv)
	if cfg.Secret == "" {
		secretLength := defSecretLength
		secretLengthEnv := os.Getenv(secretLengthEnv)
		if secretLengthEnv != "" {
			secretLength, err = strconv.Atoi(secretLengthEnv)
			if err != nil {
				return nil, fmt.Errorf("cannot convert secret length to integer: %w", err)
			}
		}
		cfg.Secret, err = security.GenerateSecret(secretLength)
		if err != nil {
			return nil, fmt.Errorf("cannot generate secret: %w", err)
		}
	}

	cfg.MaxUploadSize = defMaxUploadSize
	maxUploadSizeEnv := os.Getenv(maxUploadSizeEnv)
	if maxUploadSizeEnv != "" {
		cfg.MaxUploadSize, err = strconv.ParseInt(maxUploadSizeEnv, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cannot get max upload size from env: %w", err)
		}
	}

	portEnv := os.Getenv(portEnv)
	if portEnv != "" {
		cfg.Port = portEnv
	}

	domainString := os.Getenv(domainsEnv)
	if domainString != "" {
		cfg.AllowedDomains = strings.Split(domainString, ",")
	}

	cfg.CertFile = os.Getenv(certFileEnv)
	cfg.KeyFile = os.Getenv(keyFileEnv)

	cfg.CookieStoreKey = os.Getenv(cookieStoreKeyEnv)

	oauth2config, err := oauthConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 config: %w", err)
	}

	cfg.OAuth2Config = oauth2config

	return cfg, nil
}

func oauthConfigFromEnv() (*oauth2.Config, error) {
	cfg := &oauth2.Config{}

	cfg.ClientID = os.Getenv(oauth2ClientIDEnv)
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID not defined")
	}

	cfg.ClientSecret = os.Getenv(oauth2ClientSecretEnv)
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("client secret not defined")
	}

	cfg.RedirectURL = os.Getenv(oauth2RedirectURLEnv)
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("redirect URL not defined")
	}

	cfg.Scopes = []string{"https://www.googleapis.com/auth/gmail.send"}
	cfg.Endpoint = google.Endpoint

	return cfg, nil
}
