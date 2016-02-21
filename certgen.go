// Base on generate_cert.go from the Go Repository:
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package certgen provides high level functionality to generate X509 certificate pairs to use with TLS.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// ECDSACurve represents the supported ECDSA curves for the certificate generation
type ECDSACurve int

const (
	// P224 to select the P-224 (FIPS 186-3, section D.2.2) elliptic curve
	P224 ECDSACurve = iota
	// P256 to select the P-256 (FIPS 186-3, section D.2.3) elliptic curve
	P256
	// P384 to select the P-384 (FIPS 186-3, section D.2.4) elliptic curve
	P384
	// P521 to select the P-521 (FIPS 186-3, section D.2.5) elliptic curve
	P521
)

func (e ECDSACurve) String() string {
	switch e {
	case P224:
		return "P224"
	case P256:
		return "P256"
	case P384:
		return "P384"
	case P521:
		return "P521"
	default:
		return ""
	}
}

// ECDSACurveFromString maps from a string to the ECDSACurve constant or returns an error
func ECDSACurveFromString(s string) (ECDSACurve, error) {
	switch s {
	case "P224":
		return P224, nil
	case "P256":
		return P256, nil
	case "P384":
		return P384, nil
	case "P521":
		return P521, nil
	default:
		return P224, fmt.Errorf("Invalid or Not supported ECDSA Curve")
	}
}

// CertParams collects all the parameters for generaeting a X509 Certifice
type CertParams struct {
	Hosts      string
	ValidFrom  time.Time
	ValidFor   time.Duration
	IsCA       bool
	Rsa        bool
	RsaBits    int
	EcdsaCurve ECDSACurve
}

// NewDefaultParams returns params to generate a certificate with: RSA2048, Valid from now, valid for one year
func NewDefaultParams() *CertParams {
	cp := &CertParams{}
	cp.Hosts = "localhost"
	cp.ValidFrom = time.Now()
	cp.ValidFor = 365 * 24 * time.Hour
	cp.Rsa = true
	cp.RsaBits = 2048
	cp.EcdsaCurve = P256
	return cp
}

func (cp *CertParams) notAfter() time.Time {
	return cp.ValidFrom.Add(cp.ValidFor)
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func genCertPair(cp *CertParams) (interface{}, []byte, error) {
	var priv interface{}
	var err error
	if cp.Rsa {
		priv, err = rsa.GenerateKey(rand.Reader, cp.RsaBits)
	} else {
		switch cp.EcdsaCurve {
		case P224:
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case P256:
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case P384:
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case P521:
			priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: cp.ValidFrom,
		NotAfter:  cp.notAfter(),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(cp.Hosts, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if cp.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	return priv, derBytes, nil
}

// GenerateToMemory generates a certificate as []byte from the params.
func GenerateToMemory(cp *CertParams) (cert []byte, key []byte, err error) {
	priv, derBytes, err := genCertPair(cp)

	if err != nil {
		return
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key = pem.EncodeToMemory(pemBlockForKey(priv))
	return
}

// GenerateToFile generates a ceritificate and writes it to files
func GenerateToFile(cp *CertParams, certFile string, keyFile string) error {
	priv, derBytes, err := genCertPair(cp)

	if err != nil {
		return err
	}
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", certFile, err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Printf("written %s\n", certFile)

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyFile, err)
	}

	defer keyOut.Close()
	pem.Encode(keyOut, pemBlockForKey(priv))
	log.Printf("written %s\n", keyFile)

	return nil
}

// GenerateToWriter generates a certificate and writes then to the 2 given Writers.
func GenerateToWriter(cp *CertParams, certWriter io.Writer, keyWriter io.Writer) error {
	priv, derBytes, err := genCertPair(cp)

	if err != nil {
		return err
	}
	pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(keyWriter, pemBlockForKey(priv))
	return nil
}
