package certgentest

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x434D53/certgen"
)

func TestGenCert(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello")
	}))

	cert, key, err := certgen.GenerateToMemory(certgen.NewDefaultParams())
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := tls.X509KeyPair(cert, key)

	if err != nil {
		t.Fatal(err)
	}

	conf := &tls.Config{}
	conf.Certificates = append(conf.Certificates, certificate)
	ts.TLS = conf
	ts.StartTLS()

	defer ts.Close()

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)

	if err != nil {
		t.Fatal(err)
	}

	msg, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		t.Fatal(err)
	}

	if string(msg) != "Hello" {
		t.Fatalf("Wront message received: Expected %s, got %s", "Hello", string(msg))
	}

	if resp.TLS == nil {
		t.Fatalf("Expeted that Server used TLS. Didn't")
	}

	fmt.Printf("%x\n", resp.TLS.CipherSuite)
}
