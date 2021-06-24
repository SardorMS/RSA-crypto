package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	reader := rand.Reader
	bitSize := 4096

	// Генерация пары ключей:
	// key - приватный ключ, но внутри есть поле PublicKey, в котором - публичный
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	err = encodePrivatekey(err, key)

	encodePublicKey(err, key)

}

func encodePrivatekey(err error, key *rsa.PrivateKey) error {
	// Записываем в текстовый файл
	privateKeyFile, err := os.Create("private.key")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if cerr := privateKeyFile.Close(); cerr != nil {
			log.Println(cerr)
		}
	}()
	privateKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(privateKeyFile, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	return err
}

func encodePublicKey(err error, key *rsa.PrivateKey) {
	publicKeyFile, err := os.Create("public.key")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if cerr := publicKeyFile.Close(); cerr != nil {
			log.Println(cerr)
		}
	}()

	asn1Bytes, err := asn1.Marshal(key.PublicKey)
	publicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	err = pem.Encode(publicKeyFile, publicKey)
	if err != nil {
		log.Fatal(err)
	}
}
