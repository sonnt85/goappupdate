package goappupdate

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"os"
)

type SignatureInfo struct {
	Checksum, Signature []byte
	Hash                crypto.Hash
	PublicKey           crypto.PublicKey
}

func calculateSHA256(reader io.Reader) ([]byte, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, reader)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// CreateSignature creates a checksum, signature, hash, and public key from a file using the specified key algorithm.
// The file parameter can be either a string representing the file path or an io.Reader interface for reading the file contents.
// The keyAlgorithm parameter specifies the algorithm to be used for generating the key, such as "DSA" or "ECDSA".
// The function returns an error if any error occurs during the signature creation process.
func CreateSignature(file interface{}, keyAlgorithm string) (si *SignatureInfo, err error) {
	// Read data from file
	var reader io.Reader
	var fo *os.File
	switch f := file.(type) {
	case string:
		fo, err = os.Open(f)
		if err != nil {
			return
		}
		reader = fo
		defer fo.Close()
	case io.Reader:
		reader = f
	default:
		err = errors.New("invalid file type")
		return
	}
	si = new(SignatureInfo)

	// Create hash from file data
	si.Checksum, err = calculateSHA256(reader)
	if err != nil {
		return
	}
	si.Hash = crypto.SHA256

	// Generate private key based on the key algorithm
	var privateKey crypto.PrivateKey
	switch keyAlgorithm {
	case "DSA":
		privateKey, _, err = generateDSAKey()
		if err != nil {
			return
		}
	case "ECDSA":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return
		}
	default:
		err = errors.New("unsupported key algorithm")
		return
	}
	// Sign the hash with the private key
	si.Signature, err = signHash(si.Checksum, privateKey)
	if err != nil {
		return
	}
	// Get the public key from the private key
	si.PublicKey = getPublicKey(privateKey)
	return
}

// Generate a DSA private key and parameters
func generateDSAKey() (*dsa.PrivateKey, *dsa.Parameters, error) {
	dsaPrivateKey := new(dsa.PrivateKey)
	dsaParams := &dsaPrivateKey.Parameters

	err := dsa.GenerateParameters(dsaParams, rand.Reader, dsa.L2048N256)
	if err != nil {
		return nil, nil, err
	}

	err = dsa.GenerateKey(dsaPrivateKey, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return dsaPrivateKey, dsaParams, nil
}

// Sign the hash with the private key
func signHash(hash []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	switch key := privateKey.(type) {
	case *dsa.PrivateKey:
		r, s, err := dsa.Sign(rand.Reader, key, hash)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(dsaSignature{r, s})
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, hash)
	default:
		return nil, errors.New("unsupported key algorithm")
	}
}

// DSA signature structure
type dsaSignature struct {
	R, S *big.Int
}

// Get the public key from the private key
func getPublicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
	switch key := privateKey.(type) {
	case *dsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return nil
	}
}
