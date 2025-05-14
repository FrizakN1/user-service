package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"time"
)

type Hasher interface {
	Encrypt(value string) (string, error)
	GenerateBytes(n int) ([]byte, error)
	GenerateString(n int) (string, error)
	GenerateHash(value string) (string, error)
}

type DefaultHasher struct{}

func (e *DefaultHasher) Encrypt(value string) (string, error) {
	hash := sha256.New()

	_, err := hash.Write([]byte(value + os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (e *DefaultHasher) GenerateBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (e *DefaultHasher) GenerateString(n int) (string, error) {
	b, err := e.GenerateBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

func (e *DefaultHasher) GenerateHash(value string) (string, error) {
	str, err := e.GenerateString(16)

	if err != nil {
		return "", err
	}

	hash := sha256.New()
	_, err = hash.Write([]byte(time.Now().String() + str + value + os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
