package monitor

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net"
	"regexp"
	"time"
)

// Monitor is Monitor :)
type Monitor struct {
	Timeout time.Duration
}

// JSONCertificate is JSON structure of x509 certificate
type JSONCertificate struct {
	CommonName string    `json:"commonName"`
	Domains    []string  `json:"domains"`
	NotAfter   time.Time `json:"notAfter"`
	NotBefore  time.Time `json:"notBefore"`
	Expired    int64     `json:"expired"`
}

// NewMonitor is constructor of new instance Monitor
func NewMonitor() *Monitor {
	return &Monitor{
		Timeout: time.Second * 10,
	}
}

func parseDomain(host string) (domain string) {
	r, _ := regexp.Compile("[\\.\\-A-Za-z0-9]*")
	domain = r.FindString(host)
	return
}

// X509ToJSON is convert from x509 certificate to JSON
func X509ToJSON(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	jc := JSONCertificate{
		CommonName: cert.Subject.CommonName,
		Domains:    cert.DNSNames,
		NotAfter:   cert.NotAfter,
		NotBefore:  cert.NotBefore,
		Expired:    int64(cert.NotAfter.Sub(time.Now()).Seconds()),
	}
	j, _ := json.Marshal(jc)
	return string(j)
}

// GetCertificates is return the full certificate chain from tls connection
func (mon *Monitor) GetCertificates(host string, sni string) []*x509.Certificate {
	if len(sni) == 0 {
		sni = parseDomain(host)
	}

	tcpConn, err := net.DialTimeout("tcp", host, mon.Timeout)
	if err != nil {
		log.Println("Failed to establish TCP connection: ", err)
		return nil
	}
	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	})
	defer tcpConn.Close()

	if tlsConn == nil {
		log.Println("Can not create TLS client: ", err)
		return nil
	}
	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Now().Add(mon.Timeout))
	if err := tlsConn.Handshake(); err != nil {
		log.Println("Failed to handshake: ", err)
		return nil
	}

	state := tlsConn.ConnectionState()

	return state.PeerCertificates
}
