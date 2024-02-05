package main

import (
	"crypto/cipher"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"github.com/CurlyQuokka/speed-matcher/pkg/server"
)

const (
	DEF_MAX_UPLOAD_SIZE = 1024 * 1024 // 1MB
	DEF_PORT            = "8080"

	MAX_UPLOAD_SIZE_ENV = "MATCHER_MAX_UPLOAD_SIZE"
	PORT_ENV            = "MATCHER_PORT"
	SECRET_ENV          = "MATCHER_SECRET"
	SECRET_LENGTH_ENV   = "MATCHER_SECRET_LENGTH"
	DOMAINS_ENV         = "MATCHER_DOMAINS"
)

var (
	maxUploadSize int64
	secret        string
	port          = DEF_PORT
	cBlock        cipher.Block
	sec           *security.Security

	defaultSecretLength = 16
	domains             []string
)

func main() {
	var err error

	secret = os.Getenv(SECRET_ENV)
	if secret == "" {
		secretLength := defaultSecretLength
		secretLengthEnv := os.Getenv(SECRET_LENGTH_ENV)
		if secretLengthEnv != "" {
			secretLength, err = strconv.Atoi(secretLengthEnv)
			if err != nil {
				log.Fatalf("cannot convert secret length of %s to integer", secretLengthEnv)
			}
		}
		secret, err = security.GenerateSecret(secretLength)
		if err != nil {
			log.Fatalf("cannot generate secret %s", err.Error())
		}
	}

	otpWatchQuit := make(chan bool)
	defer close(otpWatchQuit)

	sec, err = security.New(secret, otpWatchQuit)
	if err != nil {
		log.Fatalf("cannot create security module: %s", err.Error())
	}

	maxUploadSize = DEF_MAX_UPLOAD_SIZE
	maxUploadSizeEnv := os.Getenv(MAX_UPLOAD_SIZE_ENV)
	if maxUploadSizeEnv != "" {
		maxUploadSize, err = strconv.ParseInt(maxUploadSizeEnv, 10, 64)
		if err != nil {
			log.Fatal(err)
		}
	}

	portEnv := os.Getenv(PORT_ENV)
	if portEnv != "" {
		port = portEnv
	}

	domainString := os.Getenv(DOMAINS_ENV)
	if domainString != "" {
		domains = strings.Split(domainString, ",")
	}

	s := server.New(maxUploadSize, domains, sec)

	err = s.Serve(port)
	if err != nil {
		log.Fatal(err)
	}

	otpWatchQuit <- true
}
