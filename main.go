package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/hkdf"
)

func main() {
	KMR := []byte("this is key material")
	uuid := []byte("123e4567-e89b-12d3-a456-426655440000")
	lastMac := []byte("123e4567-e89b-12d3-a456-42665544")
	plaintext := "abcdefgh"
	fmt.Println("plaintext len = ", len(plaintext))
	
	startTime := time.Now()
	stepStartTime := time.Now()
	hash256 := sha256.New

	// Generate AES key
	HKDF := hkdf.New(hash256, KMR, nil, uuid)
	aesKey := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(HKDF, aesKey); err != nil {
		panic(err)
	}
	
	stepElapsingTime := time.Since(stepStartTime)
	fmt.Println("Step Elapsing Time: ", stepElapsingTime)

	// encrypt message
	ciphertext := aesEncrypt([]byte(plaintext), aesKey)
	
	stepElapsingTime = time.Since(stepStartTime) - stepElapsingTime
	fmt.Println("Step Elapsing Time: ", stepElapsingTime)

	// Generate HMAC
	hmac := hmac.New(hash256, aesKey)
	hmac.Write([]byte(plaintext))
	resultMac := hmac.Sum(nil) // Output len is 32
	conMac := []byte{}
	conMac = append(lastMac, resultMac...)

	hmac.Write([]byte(conMac))
	finalMac := hmac.Sum(nil) // Output len is 32

	stepElapsingTime = time.Since(stepStartTime) - stepElapsingTime
	fmt.Println("Step Elapsing Time: ", stepElapsingTime)

	// Sign hash
	signature := signRSA(finalMac)
	//signature := signECDSA(finalMac)

	stepElapsingTime = time.Since(stepStartTime) - stepElapsingTime
	fmt.Println("Step Elapsing Time: ", stepElapsingTime)

	elapsingTime := time.Since(startTime)
	fmt.Printf("Result: %x %x\n", signature, ciphertext)
	fmt.Println("Signature len = ", len(signature), ", cipher len = ", len(ciphertext))
	fmt.Println("Elapsing Time: ", elapsingTime)	
}

func signECDSA(finalMac []byte) []byte{
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)
	result := r.String() + s.String()
	return []byte(result)
}

func signRSA(finalMac []byte) []byte{
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, 2048)
	signature, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, finalMac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return nil
	}
	return signature
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
