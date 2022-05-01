// Copyright 2022 Rui Lopes (ruilopes.com)

package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
)

// this implements crypto.Signer.
type amtKey struct {
	key          *rsa.PrivateKey
	amtPublicKey *rsa.PublicKey
}

func (a *amtKey) Public() crypto.PublicKey {
	return a.amtPublicKey
}

func (a *amtKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return a.key.Sign(rand, digest, opts)
}

const nullKey string = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6zYtGpppA/EPoo2KxS8/iVnAa3lQrBoGzKzu+tGkAusPEkld
r565eVHmBBBPPoAGTSg2quR6bZ3P1N0lF2zAuQa09xPehyeRimSbq+WMiMscZF0o
bd7kH1MQltRvNMqS7paitS6qngR4BqpZTm4oxnDBHuUeBaHhvhTccfJVO44qazwP
qOxF1sbyg69MgCAmkmQAkl5ApZGLaNqExDEjwh69mp0zCO3ekZUH8/FnGoWipfv1
jD/5RiZUuSCpklUvtcbyR8HjYgIDhGYU2CzRWT2YNQB2rDNC4y8oabPyjnarxGtu
4Ue70lJjHNtITUNlx4UzLSKfTI4V4gq9BjZdOQIDAQABAoIBAATCTdtR8HoB8J0L
XBltQU3YIQqLo9Q3mpedkCBHCZh9hQqLrXeWMI6B17ORWOkc0gPRonmGsetx2/ik
mNGGg8e6mQK+xivZ4xn3uyaZOGS0J1jogZ7neZogph9HIRDiYGKvbY9Y6F7WHE+W
NsRdejm5ok6ruBXJFrYv2d38VzkjN00MXEkDefgh0NPReBxsvNv8eLfhDDlC1Dfv
GtSnGJt3rCbzZqab984Gg2cR3R4ga2NPJyD2oxCG3E+aRl5kwE+Yg1WSxvRXlSzJ
43+4kjXo/K25cJpYa7185M+Qh3P4tWeUX4mmYZgCvNGbGDDiuVSufzxun8iZvmyh
AHpLYwECgYEA7VmyZBrotYiplJtcadkfHw+Hdv/YKxY3WEpW/uKr2s1FJlkbNMfW
VEkHKs3ll9a7EqKkkKaV7lCUEl3iPlQqoa1mFSsU9MvnFWy3/omZSRMNFMBXQYHf
npjRHq/jST9PLpHsod8vkSOK4d3J9sfdLLWSVPMAK+2FpjnQ1WdJvqkCgYEA/bF1
VZHr0gWQoe+aVPcnZNA3I/RCG0rOIyQM1dr4fiH48Ldcnbiru1KILrOCUDtiyfvm
j7wCEtfasE/u4go1ncv75+gkJG11YFA8IAkPfcGEkyZBRvfu2NIpFNW+US0k6BkN
1kVLqszVPsRMDGimRxXX2vVuebLpvAmj4Ai/lBECgYAVxBYB7B3PF/tFL4IoCss5
0/i+RvQR73Wf2SFlOnA8Hnrq61z9WB4lmJTZrgwSApUhPl0NDtnNAwKxNH7c7GcE
cJxd8Jd5Y4GLi27MHt45v0+Byam2ziwtpSH4SHT1cKLYSHWE2qzICJRh5i7xPJ7h
zLzgoXAwlxWciszF5TT0EQKBgQCjRkoQ55hRlDlQr4exdVwKOyOx5SuCqzNeVH5a
SNKzQyQXsLtP2yHTrrts6yVMg9wByTjLeyIOhJP/84H4Qr/dLgKTb8mLFFN9yEXa
DFrHAfxUREOw7DLxotjDywjw79AX/L/2DqUzaR85hVa4icWybHF/P4R5mNdrqPyq
XJcIMQKBgQC3Bl7Gwo8qJ3r7bCv/QcppuzDROY+u/pvZUK7W0W3MnsgrecaGZENB
yito6Tzp++Vv6gYsEWF7uQDyQXE2bI1fJVDDP1rQeAgkceLe6MnJx5T6Bp/boT61
P9OLu1fOQny2FPJ+wpuJ+FWVXBRFd9EzjJ+ba7bxO18wOXdsH8d8ew==
-----END RSA PRIVATE KEY-----
`

func main() {
	pk := flag.String("pk", "amt-public-key.pem", "AMT public key path (a PEM encoded RSA PUBLIC KEY)")
	cn := flag.String("cn", "", "Certificate Signing Request Common Name (AMT device CSR Common Name)")
	dnsNames := flag.String("dns", "", "Subject Alternative Name DNS entries (comma separated list of dns names)")
	ipAddresses := flag.String("ip", "", "Subject Alternative Name IP entries (comma separated list of IP addresses)")
	flag.Parse()

	if *pk == "" {
		log.Fatalf("you must provide the -pk argument")
	}
	if *cn == "" {
		log.Fatalf("you must provide the -cn argument")
	}
	amtPublicKeyPath := *pk

	var sanDNSNames []string
	if *dnsNames != "" {
		sanDNSNames = strings.Split(*dnsNames, ",")
	}

	var sanIPAddresses []net.IP
	if *ipAddresses != "" {
		for _, v := range strings.Split(*ipAddresses, ",") {
			ip := net.ParseIP(v)
			if ip == nil {
				log.Fatalf("failed to parse -ip %s", v)
			}
			sanIPAddresses = append(sanIPAddresses, ip)
		}
	}

	// load the amt device public key.
	amtPublicKeyPem, err := os.ReadFile(amtPublicKeyPath)
	if err != nil {
		log.Fatalf("failed to read %s: %v", amtPublicKeyPath, err)
	}
	var amtPublicKey *rsa.PublicKey
	amtPublicKeyBlock, _ := pem.Decode([]byte(amtPublicKeyPem))
	switch amtPublicKeyBlock.Type {
	case "RSA PUBLIC KEY":
		amtPublicKey, err = x509.ParsePKCS1PublicKey(amtPublicKeyBlock.Bytes)
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(amtPublicKeyBlock.Bytes)
		if err == nil {
			switch pub := pub.(type) {
			case *rsa.PublicKey:
				amtPublicKey = pub
			default:
				log.Fatalf("-pk %s file must contain an RSA public key: %v", amtPublicKeyPath, err)
			}
		}
	default:
		log.Fatalf("unknow AMT public key PEM block type %s", amtPublicKeyBlock.Type)
	}
	if err != nil {
		log.Fatalf("failed to parse -pk %s file: %v", amtPublicKeyPath, err)
	}

	// NB we are not using crypt/rand rand.Reader because we are generating a
	//    null signed csr; this is used to bound the amt device rsa public key
	//    to a csr, along with the attributes like CN and SANs.
	// NB the amt device only requires the CN.
	random := rand.New(rand.NewSource(0))
	// NB this key was initially generated with:
	// 		key, err := rsa.GenerateKey(random, 2048)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		pem.Encode(os.Stdout, &pem.Block{
	// 			Type:  "RSA PRIVATE KEY",
	// 			Bytes: x509.MarshalPKCS1PrivateKey(key),
	// 		})
	nullKeyBlock, _ := pem.Decode([]byte(nullKey))
	key, err := x509.ParsePKCS1PrivateKey(nullKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(
		random,
		&x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: *cn,
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
			DNSNames:           sanDNSNames,
			IPAddresses:        sanIPAddresses,
		},
		&amtKey{key, amtPublicKey})
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
}
