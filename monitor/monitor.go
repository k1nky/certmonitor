package monitor

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"time"
)

const (
	StateNoData = "\n"
)

// Monitor is Monitor :)
type Monitor struct {
	Ctx *Context
	DB  DBWrapper
}

func NewMonitor() *Monitor {
	return &Monitor{}
}

func (mon *Monitor) LoadConfig(filename string) error {
	ctx, err := loadConfig(filename)
	mon.Ctx = ctx
	return err
}

func (mon *Monitor) Run() {
	if err := os.MkdirAll(mon.Ctx.Data, os.ModePerm); err != nil {
		log.Fatalln(err)
	}
	if err := mon.NewDBWrapper(path.Join(mon.Ctx.Data, "local.db")); err != nil {
		log.Fatalln(err)
	}
	mon.FetchDNS()
	mon.RunWatcher()
}

func (mon *Monitor) RunWatcher() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			states := mon.DB.GetStates()
			for _, state := range states {
				mon.UpdateState(&state)
			}
		}
	}()
}

/*
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
*/

func parseDomain(host string) (domain string) {
	r, _ := regexp.Compile("[\\.\\-A-Za-z0-9]*")
	domain = r.FindString(host)

	return
}

/*
func (st State) ToJSON() string {
	j, err := json.Marshal(st)
	if err != nil {
		return StateNoData
	}
	return string(j)
}
*/

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

func fingerprint(data []byte) string {
	return fmt.Sprintf("% x", sha1.Sum(data))
}

func (mon Monitor) UpdateState(st *DBStateRow) {
	certs := mon.GetCertificates(st.Host, st.SNI)
	dbcerts := make([]DBCertRow, 0, 1)
	st.Valid = 1
	if certs == nil {
		st.Valid = -1
		mon.DB.UpdateState(st, nil)
		return
	}
	for _, cert := range certs {
		dbcerts = append(dbcerts, DBCertRow{
			CommonName:        cert.Subject.CommonName,
			NotAfter:          cert.NotAfter,
			NotBefore:         cert.NotBefore,
			Domains:           cert.DNSNames,
			Fingerprint:       fingerprint(cert.Raw),
			IssuerFingerprint: fingerprint(cert.RawIssuer),
		})
		if err := CheckCertificate(cert, ""); err != nil {
			st.Valid = 0
			st.Description = err.Error() + "\n" + st.Description
		}
	}
	if err := CheckCertificate(certs[0], st.SNI); err != nil {
		st.Valid = 0
		st.Description = err.Error() + "\n" + st.Description
	}
	mon.DB.UpdateState(st, dbcerts)
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
