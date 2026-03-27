package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func issueCertFromCSR(csrStr string, caPair *CertPair) ([]byte, error) {

	csrBytes, err := base64.RawURLEncoding.DecodeString(csrStr)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         false,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, caPair.Cert, csr.PublicKey, caPair.Key)
	if err != nil {
		log.Printf("failed to create certificate: %v", err)
		return nil, err
	}

	return certDer, nil
}

// Load or create a certificate pair, if parent is nil will be a CA certificate
//
//	commonNameTemplate: certificate CN template, eg: "My Custom CA", "My Custom CA %s"
//	newCertType: certificate type,used when create a new certificate pair, e.g.: "RSA" (2048), "ECDSA" (P256)
//	serverName: comma-separated server dns name or ip address, eg: "localhost, 127.0.0.1"
func loadOrCreateCert(certPath string, keyPath string, commonNameTemplate string, newCertType string, serverName string, parent *CertPair, verifyParent bool) (*CertPair, error) {
	certData, err := os.ReadFile(certPath)
	if err == nil {
		certBlock, _ := pem.Decode(certData)
		if certBlock == nil {
			return nil, fmt.Errorf("failed to decode certificate PEM")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		keyBlock, _ := pem.Decode(keyData)
		if keyBlock == nil {
			return nil, fmt.Errorf("failed to decode key PEM")
		}
		key, err := parsePrivateKey(keyBlock)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		if err := verifyCertKeyPair(cert, key); err != nil {
			return nil, fmt.Errorf("certificate and key do not match: %w", err)
		}

		if verifyParent && parent != nil {
			if err := cert.CheckSignatureFrom(parent.Cert); err != nil {
				return nil, fmt.Errorf("certificate is not signed by parent: %w", err)
			}
		}

		return &CertPair{Cert: cert, Key: key}, nil
	}

	var priv crypto.Signer
	var pub crypto.PublicKey

	switch newCertType {
	case "RSA":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		priv = rsaKey
		pub = &rsaKey.PublicKey
	case "ECDSA":
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		priv = ecdsaKey
		pub = &ecdsaKey.PublicKey

	default:
		return nil, fmt.Errorf("unsupported certificate type: %s", newCertType)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	commonName := strings.Replace(commonNameTemplate, "%s", serial.Text(16)[:8], 1)
	var notAfter time.Time

	var dnsNames []string
	var ipAddresses []net.IP
	var keyUsage x509.KeyUsage
	if parent == nil {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		notAfter = time.Now().AddDate(10, 0, 0)
	} else {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		notAfter = parent.Cert.NotAfter
		names := strings.Split(serverName, ",")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if net.ParseIP(name) != nil {
				ipAddresses = append(ipAddresses, net.ParseIP(name))
			} else {
				dnsNames = append(dnsNames, name)
			}
		}
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	var issuer *x509.Certificate
	var signer crypto.Signer

	if parent == nil {
		issuer = template
		signer = priv
	} else {
		issuer = parent.Cert
		signer = parent.Key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY, os.FileMode(0644))
	if err != nil {
		return nil, fmt.Errorf("failed to write certificate: %w", err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if parent != nil && parent.Cert != nil {
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: parent.Cert.Raw})
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close certificate file: %w", err)
	}

	var keyBytes []byte
	var keyType string
	switch newCertType {
	case "RSA":
		keyBytes = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
		keyType = "RSA PRIVATE KEY"
	case "ECDSA":
		keyBytes, err = x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		keyType = "EC PRIVATE KEY"
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return &CertPair{Cert: cert, Key: priv}, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key does not implement crypto.Signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type: %s", block.Type)
	}
}

func verifyCertKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	testData := []byte("letsacme-cert-key-pair-verification")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	var sig []byte
	var sigAlg x509.SignatureAlgorithm
	switch key.(type) {
	case *ecdsa.PrivateKey:
		sigAlg = x509.ECDSAWithSHA256
		var err error
		sig, err = key.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to sign with private key: %w", err)
		}
	case *rsa.PrivateKey:
		sigAlg = x509.SHA256WithRSA
		var err error
		sig, err = key.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to sign with private key: %w", err)
		}
	case ed25519.PrivateKey:
		sigAlg = x509.PureEd25519
		var err error
		sig, err = key.Sign(rand.Reader, testData, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("failed to sign with private key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key type for verification: %T", key)
	}

	err := cert.CheckSignature(sigAlg, testData, sig)
	if err != nil {
		return fmt.Errorf("certificate and private key do not match: %w", err)
	}

	if !keysEqual(cert.PublicKey, key.Public()) {
		return errors.New("certificate public key does not match private key")
	}

	return nil
}

func keysEqual(a, b crypto.PublicKey) bool {
	switch pub := b.(type) {
	case *ecdsa.PublicKey:
		return pub.Equal(a)
	case *rsa.PublicKey:
		return pub.Equal(a)
	case ed25519.PublicKey:
		return pub.Equal(a)
	default:
		return false
	}
}
