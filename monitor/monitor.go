package monitor

import (
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
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

func (mon *Monitor) worker(jobs <-chan DBStateRow) {
	for state := range jobs {
		mon.UpdateState(&state)
		mon.DB.UpdateState(&state)
	}
}

func (mon *Monitor) RunWatcher() {
	delay := time.Second * time.Duration(mon.Ctx.WatcherDelay)
	go func() {
		jobs := make(chan DBStateRow)
		for i := 0; i < mon.Ctx.MaxThreads; i++ {
			go mon.worker(jobs)
		}
		for {
			states := mon.DB.GetStates()
			for _, state := range states {
				jobs <- state
			}
			time.Sleep(delay)
		}
	}()
}

func NewState(host string, sni string) *DBStateRow {
	if len(sni) == 0 {
		sni = parseDomain(host)
	}
	return &DBStateRow{
		Host:         host,
		SNI:          sni,
		Certificates: nil,
		Valid:        UnknownState,
	}
}

func parseDomain(host string) (domain string) {
	r, _ := regexp.Compile("[\\.\\-A-Za-z0-9]*")
	domain = r.FindString(host)

	return
}

func (mon Monitor) UpdateState(st *DBStateRow) {
	certs := mon.GetCertificates(st.Host, st.SNI)
	st.Certificates = make([]DBCertRow, 0, 1)
	st.Valid = ValidState
	if certs == nil {
		st.Valid = UnknownState
		return
	}
	for _, cert := range certs {
		st.Certificates = append(st.Certificates, DBCertRow{
			CommonName:        strings.ReplaceAll(cert.Subject.CommonName, "'", "''"),
			NotAfter:          cert.NotAfter,
			NotBefore:         cert.NotBefore,
			Domains:           cert.DNSNames,
			Fingerprint:       fingerprint(cert.Raw),
			IssuerFingerprint: fingerprint(cert.RawIssuer),
			Expired:           int(cert.NotAfter.Sub(time.Now()).Seconds()),
		})
		if err := CheckCertificate(cert, ""); err != nil {
			st.Valid = InvalidState
			st.Description = err.Error() + "\n" + st.Description
		}
	}
	if err := CheckCertificate(certs[0], st.SNI); err != nil {
		st.Valid = InvalidState
		st.Description = err.Error() + "\n" + st.Description
	}
}
