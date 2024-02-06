package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CurlyQuokka/speed-matcher/pkg/security"
)

const (
	defMaxUploadSize = 1024 * 1024 // 1MB
	defPort          = "8080"

	maxUploadSizeEnv = "MATCHER_MAX_UPLOAD_SIZE"
	portEnv          = "MATCHER_PORT"
	secretEnv        = "MATCHER_SECRET"
	secretLengthEnv  = "MATCHER_SECRET_LENGTH"
	domainsEnv       = "MATCHER_DOMAINS"

	defSecretLength = 16
)

type Config struct {
	AllowedDomains []string
	MaxUploadSize  int64
	Port           string
	Secret         string
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

	return cfg, nil
}
