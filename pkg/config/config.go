package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CurlyQuokka/speed-matcher/pkg/security"
)

const (
	DEF_MAX_UPLOAD_SIZE = 1024 * 1024 // 1MB
	DEF_PORT            = "8080"

	MAX_UPLOAD_SIZE_ENV = "MATCHER_MAX_UPLOAD_SIZE"
	PORT_ENV            = "MATCHER_PORT"
	SECRET_ENV          = "MATCHER_SECRET"
	SECRET_LENGTH_ENV   = "MATCHER_SECRET_LENGTH"
	DOMAINS_ENV         = "MATCHER_DOMAINS"

	DEF_SECRET_LENGTH = 16
)

type Config struct {
	AllowedDomains []string
	MaxUploadSize  int64
	Port           string
	Secret         string
}

func FromEnv() (*Config, error) {
	cfg := &Config{
		Port: DEF_PORT,
	}

	var err error

	cfg.Secret = os.Getenv(SECRET_ENV)
	if cfg.Secret == "" {
		secretLength := DEF_SECRET_LENGTH
		secretLengthEnv := os.Getenv(SECRET_LENGTH_ENV)
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

	cfg.MaxUploadSize = DEF_MAX_UPLOAD_SIZE
	maxUploadSizeEnv := os.Getenv(MAX_UPLOAD_SIZE_ENV)
	if maxUploadSizeEnv != "" {
		cfg.MaxUploadSize, err = strconv.ParseInt(maxUploadSizeEnv, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cannot get max upload size from env: %w", err)
		}
	}

	portEnv := os.Getenv(PORT_ENV)
	if portEnv != "" {
		cfg.Port = portEnv
	}

	domainString := os.Getenv(DOMAINS_ENV)
	if domainString != "" {
		cfg.AllowedDomains = strings.Split(domainString, ",")
	}

	return cfg, nil
}
