package slowseeder

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func Example_generateRSA() {
	r, _ := New([]byte("slowseeder"), 1000, 3, 1024*16, 1)
	k, _ := rsa.GenerateKey(r, 2048)
	e := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
	fmt.Println(string(e))
}
