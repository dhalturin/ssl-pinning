/*
Copyright © 2025 Denis Khalturin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
// prettier-ignore-end
package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Signer provides cryptographic signing functionality using RSA private key.
// It signs JSON data after canonicalization using SHA-512 hash and PKCS1v15 signature scheme.
type Signer struct {
	privateKey *rsa.PrivateKey
}

// NewSigner creates and initializes a new Signer instance from a PEM-encoded private key file.
// The private key must be in PKCS8 format and of type RSA.
// Returns an error if the file cannot be read, PEM decoding fails, or key parsing fails.
func NewSigner(privateKeyPath string) (*Signer, error) {
	privPem, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(privPem)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not of type *rsa.PrivateKey")
	}

	return &Signer{
		privateKey: rsaPriv,
	}, nil
}

// Sign signs JSON data using RSA-SHA512 signature algorithm.
// It performs three steps:
// 1. Canonicalizes the JSON data to ensure consistent representation
// 2. Computes SHA-512 hash of the canonical JSON
// 3. Signs the hash using RSA PKCS1v15 and returns base64-encoded signature
// Returns an error if canonicalization or signing fails.
func (s *Signer) Sign(data []byte) (string, error) {
	canonical, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	hashed := sha512.Sum512(canonical)

	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA512, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JSON: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
