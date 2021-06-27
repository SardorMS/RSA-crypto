package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Go Alif Academy"},
			Country:      []string{"TJ"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	reader := rand.Reader
	bitSize := 4096

	// Генерация пары ключей:
	// caKey - приватный ключ, но внутри есть поле PublicKey, в котором - публичный.
	caKey, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	// Создаём сертификат для CA (Certificate Authority)
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}

	err = encodePrivateKey(err, caKey, "ca-private.key")
	if err != nil {
		log.Fatal(err)
	}

	err = encodePublicKey(err, &caKey.PublicKey, "ca-piblic.key")
	if err != nil {
		log.Fatal(err)
	}

	err = encodeCert(caBytes, "ca.crt")
	if err != nil {
		log.Fatal(err)
	}

	// Создаём сертификат для сервера.
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:       []string{"Go Alif Academy"},
			OrganizationalUnit: []string{"Dev"},
			Country:            []string{"TJ"},
		},
		DNSNames:    []string{"go.alif.hack"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		//SubjectKeyId: []byte(1, 2, 3, 4, 5, 6),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	// Издаём сертификат для сервера,
	// подписанный приватным ключом CA (и указываем "родительский сертификат")
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}

	err = encodePrivateKey(err, certKey, "server-private.key")
	if err != nil {
		log.Fatal(err)
	}

	err = encodePublicKey(err, &certKey.PublicKey, "server-piblic.key")
	if err != nil {
		log.Fatal(err)
	}

	err = encodeCert(certBytes, "server.crt")
	if err != nil {
		log.Fatal(err)
	}
}

func encodePrivateKey(err error, key *rsa.PrivateKey, path string) error {
	// Записываем в текстовый файл
	privateKeyFile, err := os.Create(path)
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

func encodePublicKey(err error, key *rsa.PublicKey, path string) error {
	publicKeyFile, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if cerr := publicKeyFile.Close(); cerr != nil {
			log.Println(cerr)
		}
	}()

	// asn1Bytes, err := asn1.Marshal(key)
	// ecdsaKey := key.(*ecdsa.PublicKey)
	encKey, err := x509.MarshalPKIXPublicKey(key)
	publicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: encKey,
	}

	err = pem.Encode(publicKeyFile, publicKey)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func encodeCert(cert []byte, path string) error {
	// записываем в текстовый файл
	certFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := certFile.Close(); cerr != nil {
			log.Println(err)
		}
	}()

	data := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	err = pem.Encode(certFile, data)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}
