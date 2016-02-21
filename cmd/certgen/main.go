package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/0x434D53/certgen"
)

var (
	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521")
	certFile   = flag.String("certfile", "cert.pem", "Filename for the Certificate File")
	keyFile    = flag.String("pemfile", "key.pem", "Filename for the Key File")
)

func main() {
	flag.Parse()

	if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	cp := &certgen.CertParams{}
	cp.Hosts = *host

	ecdsa, err := certgen.ECDSACurveFromString(*ecdsaCurve)

	if err != nil {
		cp.Rsa = true
		cp.RsaBits = *rsaBits
	} else {
		cp.Rsa = false
		cp.EcdsaCurve = ecdsa
	}

	if len(*validFrom) == 0 {
		cp.ValidFrom = time.Now()
	} else {
		cp.ValidFrom, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	cp.ValidFor = *validFor
	cp.IsCA = *isCA

	err = certgen.GenerateToFile(cp, *certFile, *keyFile)

	if err != nil {
		fmt.Printf("Couldn't generate certs: %s\n", err)
	}
}
