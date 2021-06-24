package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"os"
)

func main() {
	publicKeyBytes, err := os.ReadFile("public.key")
	if err != nil {
		log.Fatal(err)
	}
	publicKey, err := decodePublicKey(publicKeyBytes)

	// шифруем
	plaintext := []byte("Go rulezzz")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("HEX: %x", ciphertext)

	encodedText := hex.EncodeToString(ciphertext)
	data := []byte(encodedText)
	
	err = os.WriteFile("ciphertext.txt", data, 0777)
	if err != nil {
		log.Fatal(err)
	}	

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
