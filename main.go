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
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/obscuren/ecies"
	"golang.org/x/crypto/hkdf"
)

func main() {
	var ModeRSA, ModeECDSA, plaintextSizeBenchmark, seedExchange bool
	flag.BoolVar(&ModeRSA, "rsa", false, "Set to RSA mode.")
	flag.BoolVar(&ModeECDSA, "ecdsa", true, "Set to ECDSA mode.")
	flag.BoolVar(&plaintextSizeBenchmark, "benchmark", false, "Run benchmark for different plaintext length.")
	flag.BoolVar(&seedExchange, "seed", false, "Set to key exchange example.")
	flag.Parse()

	if seedExchange {
		registerSeed()
	} else if plaintextSizeBenchmark {
		startLen := 10
		endLen := 200
		step := 10
		plaintext := ""
		stepSubstring := ""
		for i := 0; i < step; i++ {
			stepSubstring += "a"
		}

		for i := startLen; i < endLen+1; i += step {
			plaintext += stepSubstring
			fmt.Println("=============length = ", i, "=============")
			sendMessage(ModeRSA, ModeECDSA, plaintext)
		}
	} else {
		plaintext := "{\"consumption\":\"12kWh\"}"
		sendMessage(ModeRSA, ModeECDSA, plaintext)
	}

}

func registerSeed() {
	seed := "THIS9IS9AN9ADDRESS9USED9BY9TAGNLEACCELERATOR9999999999999999999999999999999999999"

	startTime := time.Now()
	stepStartTime := time.Now()
	k, err := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		panic(err)
	}
	stepElapsingTime := time.Since(stepStartTime)
	fmt.Println("Generate Key Elapsing Time: ", stepElapsingTime)

	ciphertext, err := ecies.Encrypt(rand.Reader, &k.PublicKey, []byte(seed))
	if err != nil {
		panic(err)
	}
	stepElapsingTime = time.Since(stepStartTime)
	fmt.Println("Encrypt Seed Elapsing Time: ", stepElapsingTime)

	_, err = k.Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	stepElapsingTime = time.Since(stepStartTime)
	fmt.Println("Decrypt Seed Elapsing Time: ", stepElapsingTime)
	elapsingTime := time.Since(startTime)
	fmt.Println("Total Elapsing Time: ", elapsingTime)
}

func sendMessage(ModeRSA, ModeECDSA bool, plaintext string) {
	KMR := []byte("this is key material")                  // This is hardware secret
	uuid := []byte("123e4567-e89b-12d3-a456-426655440000") // This is shared information which can be used to change different AES key set
	lastMac := []byte("123e4567-e89b-12d3-a456-42665544")

	startTime := time.Now()
	hash256 := sha256.New

	// Generating Signing Key pair
	stepStartTime := time.Now()
	var ecdsaPrivateKey *ecdsa.PrivateKey
	var rsaPrivateKey *rsa.PrivateKey
	var err error
	// RSA Key size in 3072 bits is in the same security level as ECDSA with a Key in 256 bits
	if ModeRSA {
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 3072)
	} else if ModeECDSA {
		ecdsaPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
	}
	stepElapsingTime := time.Since(stepStartTime)
	fmt.Println("Generate Key Pair Elapsing Time: ", stepElapsingTime)
	keyGenerateTime := stepElapsingTime

	// Generate AES key
	stepStartTime = time.Now()
	HKDF := hkdf.New(hash256, KMR, nil, uuid)
	aesKey := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(HKDF, aesKey); err != nil {
		panic(err)
	}
	stepElapsingTime = time.Since(stepStartTime)
	fmt.Println("Generate AES Key Elapsing Time: ", stepElapsingTime)

	// encrypt message
	ciphertext := aesEncrypt([]byte(plaintext), aesKey)

	stepElapsingTime = time.Since(stepStartTime) - stepElapsingTime
	fmt.Println("encrypt message Elapsing Time: ", stepElapsingTime)

	// Generate HMAC
	stepStartTime = time.Now()
	hmac := hmac.New(hash256, aesKey)
	hmac.Write([]byte(plaintext))
	resultMac := hmac.Sum(nil) // Output len is 32
	conMac := []byte{}
	conMac = append(lastMac, resultMac...)

	hmac.Write([]byte(conMac))
	finalMac := hmac.Sum(nil) // Output len is 32

	stepElapsingTime = time.Since(stepStartTime)
	fmt.Println("Generate HMAC Elapsing Time: ", stepElapsingTime)

	// Sign hash
	stepStartTime = time.Now()
	var signature []byte
	if ModeRSA {
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, finalMac)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		}

	} else if ModeECDSA {
		r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, finalMac[:])
		if err != nil {
			panic(err)
		}
		fmt.Printf("r: %x, s: %x\n", (r), (s))
		signature = append(r.Bytes(), s.Bytes()...)

	}
	stepElapsingTime = time.Since(stepStartTime)
	fmt.Println("Signing Elapsing Time: ", stepElapsingTime)

	elapsingTime := time.Since(startTime)
	fmt.Println("==============Result==============")
	//fmt.Printf("Signature len: %d, Cipher len: %d\n", len(signature), len(ciphertext))
	fmt.Printf("Signature: %x, Cipher: %x\n", (signature), (ciphertext))
	fmt.Println("Total Elapsing Time: ", elapsingTime)
	fmt.Println("Without Key Generation Elapsing Time: ", elapsingTime-keyGenerateTime)
	fmt.Println("==============End==============")
	fmt.Println("")
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
