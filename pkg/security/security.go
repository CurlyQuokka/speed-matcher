package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	otpLength     = 16 // must be multiple of 4
	otpTries      = 10
	otpExpiration = 180
	base64denom   = 4
	base64mul     = 3
)

type Security struct {
	allowedDomains []string
	secret         string
	cblock         cipher.Block
	otps           map[string]time.Time
	quit           chan bool
}

func New(secret string, allowedDomains []string, quit chan bool) (*Security, error) {
	s := &Security{
		allowedDomains: allowedDomains,
		secret:         secret,
		otps:           make(map[string]time.Time),
		quit:           quit,
	}

	cBlock, err := aes.NewCipher([]byte(s.secret))
	if err != nil {
		return nil, fmt.Errorf("error creating new cblock for AES: %w", err)
	}
	s.cblock = cBlock

	go s.WatchOTPs()

	return s, nil
}

func (s *Security) Encrypt(value string) (string, error) {
	byteValue := []byte(value)
	cipherData := make([]byte, aes.BlockSize+len(byteValue))
	iv := cipherData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("error generating IV: %w", err)
	}

	cfb := cipher.NewCFBEncrypter(s.cblock, iv)
	cfb.XORKeyStream(cipherData[aes.BlockSize:], byteValue)

	return base64.StdEncoding.EncodeToString(cipherData), nil
}

func (s *Security) Decrypt(value string) (string, error) {
	cipherData, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 value: %w", err)
	}

	if len(cipherData) < aes.BlockSize {
		return "", errors.New("invalid ciphertext block size")
	}

	iv := cipherData[:aes.BlockSize]
	cipherData = cipherData[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(s.cblock, iv)
	cfb.XORKeyStream(cipherData, cipherData)

	return string(cipherData), nil
}

func GenerateSecret(length int) (string, error) {
	// base64 length calculation formula is 4*[n/3] without padding
	secret := make([]byte, (length/base64denom)*base64mul)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("error generating secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(secret), nil
}

func (s *Security) GenerateOTP() (string, error) {
	var key string
	var err error
	if s.otps == nil {
		s.otps = make(map[string]time.Time)
	}
	for i := 0; i < otpTries; i++ {
		key, err = GenerateSecret(otpLength)
		if err != nil {
			return "", fmt.Errorf("unable to generate OTP: %w", err)
		}
		if _, exists := s.otps[key]; exists {
			if i >= otpTries-1 {
				return "", fmt.Errorf("unable to generate OTP in %d tries", otpTries)
			}
			continue
		}
		s.otps[key] = time.Now()
		break
	}
	return key, nil
}

func (s *Security) CheckOTP(key string) bool {
	_, exists := s.otps[key]
	return exists
}

func (s *Security) WatchOTPs() {
	for {
		for key, t := range s.otps {
			diff := time.Since(t)
			if diff.Seconds() > otpExpiration {
				delete(s.otps, key)
			}
		}
		select {
		case <-s.quit:
			s.quit <- true
			return
		default:
		}
		time.Sleep(time.Second)
	}
}

func (s *Security) IsEmailAuthorized(email string) (bool, error) {
	for _, domain := range s.allowedDomains {
		domainRegex := "^[\\w-\\.]+@" + strings.ReplaceAll(domain, ".", "\\.")
		r, err := regexp.Compile(domainRegex)
		if err != nil {
			return false, fmt.Errorf("error compiling regex: %w", err)
		}
		if r.MatchString(email) {
			return true, nil
		}
	}
	return false, nil
}
