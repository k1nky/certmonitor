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
	return fmt.Sprintf("% x", sha1.Sum(data))
}

// GetCertificates is return the full certificate chain from tls connection
func (mon Monitor) GetCertificates(host string, sni string) []*x509.Certificate {

	timeout := time.Duration(mon.Ctx.TLSTimeout) * time.Second
	tcpConn, err := net.DialTimeout("tcp", host, timeout)
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
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		log.Println("Failed to handshake: ", err)
		return nil
	}
	state := tlsConn.ConnectionState()

	return state.PeerCertificates
}
