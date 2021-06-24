package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"
)

func main() {
	// Генерируем случайный ключ
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	// Печатаем в формате HEX
	log.Printf("%x", key)

	// Наше исходное сообщение
	plaintext := []byte("Important message")
	// Шифруем
	ciphertext, nonce, err := encrypt(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	// Печатаем в формате HEX
	log.Printf("%x", ciphertext)
	log.Printf("%x", nonce)

	// Расшифровываем
	decryptedtext, err := decrypt(ciphertext, nonce, key)
	if err != nil {
		log.Fatal(err)
	}

	// Печатаем расшифрованный текст
	log.Printf("%x", decryptedtext)

}

func encrypt(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error) {

	// экземпляр шифра AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// создаём nonce (number used once)
	// по правилам для каждого шифрвания нам нужен ключ и nonce
	// примечание: nonce лучше делать со счётчиком
	nonceSize := gcm.NonceSize()
	nonce = make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Seal шифрует текст и возвращает зашифрованные данные
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func decrypt(ciphertext []byte, nonce []byte, key []byte) ([]byte, error) {

	// экземпляр шифра AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Seal шифрует текст и возвращает зашифрованные данные
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
