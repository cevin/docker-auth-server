package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

var lists []string

func main() {

	// 准备清理的文件
	lists = make([]string, 0)

	defer func() {
		if err := recover(); err != nil {
			for _, val := range lists {
				os.Remove(val)
			}
			panic(err)
		}
	}()

	// 创建CA证书
	ca := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  nil,
			Country:       []string{"CN"},
			Province:      nil,
			Locality:      nil,
			StreetAddress: nil,
			PostalCode:    nil,
			CommonName:    "BDY Global Security ROOT CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(100, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	caCrtBytes, err := x509.CreateCertificate(rand.Reader, &ca, &ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	// 创建应用证书
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:    []string{"CN"},
			CommonName: "BDY Private Container Registry Service",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(100, 0, 0),
		IsCA:         false,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	certCrtBytes, err := x509.CreateCertificate(rand.Reader, &cert, &ca, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	// ca
	caPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCrtBytes,
	})
	caKeyDer, _ := x509.MarshalPKCS8PrivateKey(caPrivateKey)
	caKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: caKeyDer,
	})

	// cert
	crtPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certCrtBytes,
	})
	crtKeyDer, _ := x509.MarshalPKCS8PrivateKey(certPrivateKey)
	crtKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: crtKeyDer,
	})

	writeFile("./ca.crt", string(caPem))
	writeFile("./ca.key", string(caKeyPem))
	writeFile("./cert.crt", string(crtPem))
	writeFile("./cert.key", string(crtKeyPem))
}

func writeFile(filename, content string) {
	if err := ioutil.WriteFile(filename, []byte(content), fs.ModeSetuid|fs.ModeSetgid); err != nil {
		panic(err)
	}

	lists = append(lists, filename)
}
