package monitor

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

// CheckCertificate checks certificate chain for the host
func CheckCertificate(cert *x509.Certificate, hostname string) error {

	if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		msg := fmt.Sprintf("Certificate %s is expired or inactived yet", cert.Subject.CommonName)
		return errors.New(msg)
	}
	if len(hostname) == 0 {
		return nil
	}
	return cert.VerifyHostname(hostname)
}

func fingerprint(data []byte) string {
	return fmt.Sprintf("%x", sha1.Sum(data))
}

// GetCertificates returns the full certificate chain from TLS connection
func (mon Monitor) GetCertificates(host string, sni string) []*x509.Certificate {

	timeout := time.Duration(mon.Cfg.TLSTimeout) * time.Second
	tcpConn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		log.Printf("Failed to establish TCP connection to %s: %s\n", host, err)
		return nil
	}
	defer tcpConn.Close()

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	})
	if tlsConn == nil {
		log.Printf("Can not create TLS client for %s: %s\n", host, err)
		return nil
	}
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("Failed to handshake with %s: %s\n", host, err)
		return nil
	}
	state := tlsConn.ConnectionState()

	return state.PeerCertificates
}
