// Package server wraps http.ListenAndServeTLS such that it generates self signed certificates on the fly automatically
package server

import (
	"crypto/tls"
	"net/http"

	"github.com/0x434D53/certgen"
)

// ListenAndServeTLS creates a new server like http.ListenAndServeTLS but creates a self-signed certificate on the fly.
// Warning: Since it's not a trusted certificate chain, the golang http-server will log http2: server: error reading preface... when connecting to the server.
func ListenAndServeTLS(addr string, handler http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: handler}
	cert, key, err := certgen.GenerateToMemory(certgen.NewDefaultParams())
	if err != nil {
		return err
	}

	certificate, err := tls.X509KeyPair(cert, key)

	if err != nil {
		return err
	}

	conf := &tls.Config{}
	conf.Certificates = append(conf.Certificates, certificate)
	srv.TLSConfig = conf

	return srv.ListenAndServeTLS("", "")
}
