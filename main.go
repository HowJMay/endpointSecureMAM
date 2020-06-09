package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

func main() {
	KMR := []byte("this is key material")
	uuid := []byte("123e4567-e89b-12d3-a456-426655440000")
	lastMac := []byte("123e4567-e89b-12d3-a456-42665544")
	plaintext := "abcdefgh"
	// payload2 := "abc1"
	hash256 := sha256.New

	// Generate AES key
	HKDF := hkdf.New(hash256, KMR, nil, uuid)
	aesKey := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(HKDF, aesKey); err != nil {
		panic(err)
	}

	// encrypt message
	ciphertext := aesEncrypt([]byte(plaintext), aesKey)

	// Generate HMAC
	hmac := hmac.New(hash256, aesKey)
	hmac.Write([]byte(plaintext))
	resultMac := hmac.Sum(nil) // Output len is 32
	conMac := []byte{}
	conMac = append(lastMac, resultMac...)
	
	hmac.Write([]byte(conMac))
	finalMac := hmac.Sum(nil) // Output len is 32

	// Sign hash
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, 2048)
	signature, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, finalMac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}

	fmt.Printf("Result: %x %x\n", signature, ciphertext)
	fmt.Println("Signature len = ", len(signature), ", cipher len = ", len(ciphertext))
}	

func aesEncrypt(input, key []byte) []byte {
	// padding 
	if input == nil || len(input) == 0 {
		return nil
	}
	n := aes.BlockSize - (len(input) % aes.BlockSize)
	pb := make([]byte, len(input)+n)
	copy(pb, input)
	copy(pb[len(input):], bytes.Repeat([]byte{byte(n)}, n))
	
	// encryption
	ciphertext := make([]byte, aes.BlockSize+len(pb))
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = byte(i)
	}
	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(ciphertext[aes.BlockSize:], pb)
	return ciphertext
}
