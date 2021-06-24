package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
)

func main() {
	publicKeyBytes, err := os.ReadFile("asymmetric/key/public.key")
	if err != nil {
		log.Fatal(err)
	}
	publicKey, err := decodePublicKey(publicKeyBytes)

	// шифруем
	plaintext := []byte("ImportantMessage")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%x", ciphertext)

	privateKeyBytes, err := os.ReadFile("asymmetric/key/private.key")
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := decodePrivateKey(privateKeyBytes)

	// расшифровываем
	decryptedtext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%x", decryptedtext)
}

func decodePublicKey(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("can't decode pem block")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func decodePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("can't decode pem block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
