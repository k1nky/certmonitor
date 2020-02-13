package monitor

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"time"
)

const (
	StateNoData = "\n"
)

// Monitor is Monitor :)
type Monitor struct {
	Timeout time.Duration
}

type State struct {
	Host         string `json:"host"`
	SNI          string `json:"sni"`
	Valid        bool   `json:"valid"`
	Description  string `json:"description"`
	Certificates []JSONCertificate
}

// JSONCertificate is JSON structure of x509 certificate
type JSONCertificate struct {
	CommonName string    `json:"commonName"`
	Issuer     string    `json:"issuer"`
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

func NewState(host string, sni string) *State {
	if len(sni) == 0 {
		sni = parseDomain(host)
	}
	return &State{
		Host:         host,
		SNI:          sni,
		Certificates: make([]JSONCertificate, 0, 1),
		Valid:        true,
		Description:  "",
	}
}

func parseDomain(host string) (domain string) {
	r, _ := regexp.Compile("[\\.\\-A-Za-z0-9]*")
	domain = r.FindString(host)

	return
}

func (st State) ToJSON() string {
	j, err := json.Marshal(st)
	if err != nil {
		return StateNoData
	}
	return string(j)
}

func CheckCertificate(cert *x509.Certificate, hostname string) error {
	if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		msg := fmt.Sprintf("Certificate %s is expired or not actived yet", cert.Subject.CommonName)
		return errors.New(msg)
	}
	if len(hostname) == 0 {
		return nil
	}
	return cert.VerifyHostname(hostname)
}

func (mon Monitor) UpdateState(st *State) {
	certs := mon.GetCertificates(st.Host, st.SNI)
	if certs == nil {
		return
	}
	for _, cert := range certs {
		st.Certificates = append(st.Certificates, JSONCertificate{
			CommonName: cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotAfter:   cert.NotAfter,
			NotBefore:  cert.NotBefore,
			Domains:    cert.DNSNames,
			Expired:    int64(cert.NotAfter.Sub(time.Now()).Seconds()),
		})
		if err := CheckCertificate(cert, ""); err != nil {
			st.Valid = false
			st.Description = err.Error() + "\n" + st.Description
		}
	}
	if err := CheckCertificate(certs[0], st.SNI); err != nil {
		st.Valid = false
		st.Description = err.Error() + "\n" + st.Description
	}
}

// GetCertificates is return the full certificate chain from tls connection
func (mon Monitor) GetCertificates(host string, sni string) []*x509.Certificate {

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
