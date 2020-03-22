package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	warmUpDealy = 10
)

// Monitor is Monitor :)
type Monitor struct {
	Cfg        *Config
	ConfigFile string
	Ctx        context.Context
	DB         DBWrapper
	stop       chan interface{}
}

func NewMonitor() *Monitor {
	return &Monitor{
		Ctx:  context.Background(),
		stop: make(chan interface{}),
	}
}

func (mon *Monitor) LoadConfig(filename string) (err error) {
	mon.ConfigFile = filename
	mon.Cfg, err = loadConfig(filename)
	return
}

func (mon *Monitor) Run() {
	ctxWithCancel, cancelFunction := context.WithCancel(mon.Ctx)
	go func() {
		<-mon.stop
		cancelFunction()
	}()
	if err := os.MkdirAll(mon.Cfg.WorkDir, os.ModePerm); err != nil {
		log.Fatalln(err)
	}
	if mon.DB = OpenDB(path.Join(mon.Cfg.WorkDir, "local.db")); mon.DB == nil {
		return
	}

	mon.DB.RunWriter(ctxWithCancel)
	mon.FetchDNS(ctxWithCancel)
	mon.RunWatcher(ctxWithCancel)
}

func (mon *Monitor) Stop() {
	mon.stop <- true
	mon.DB.Close()
}

func (mon *Monitor) worker(ctx context.Context, jobs <-chan DBStateRow) {
	for {
		select {
		case state := <-jobs:
			mon.UpdateState(&state)
			mon.DB.UpdateState(&state)
		case <-ctx.Done():
			return
		}
	}
}

func (mon *Monitor) RunWatcher(ctx context.Context) {
	delay := time.Second * time.Duration(mon.Cfg.WatcherDelay)
	ticker := time.NewTicker(delay)
	go func() {
		time.Sleep(time.Second * time.Duration(warmUpDealy))
		jobs := make(chan DBStateRow)
		for i := 0; i < mon.Cfg.MaxThreads; i++ {
			go mon.worker(ctx, jobs)
		}
		for {
			mon.MaintainDB()
			states := mon.DB.GetStatesBy("")
			for _, state := range states {
				jobs <- state
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
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
	st.Description = ""

	if certs == nil {
		st.Valid = UnknownState
		return
	}
	sni := st.SNI
	for _, cert := range certs {
		st.Certificates = append(st.Certificates, DBCertRow{
			CommonName:  strings.ReplaceAll(cert.Subject.CommonName, "'", "''"),
			NotAfter:    cert.NotAfter,
			NotBefore:   cert.NotBefore,
			Domains:     fmt.Sprintf("%s", cert.DNSNames),
			Fingerprint: fingerprint(cert.Raw),
			SubjectHash: fingerprint(cert.RawSubject),
			IssuerHash:  fingerprint(cert.RawIssuer),
			Expired:     int(cert.NotAfter.Sub(time.Now()).Seconds()),
		})
		if err := CheckCertificate(cert, sni); err != nil {
			st.Valid = InvalidState
			st.Description = st.Description + "\n" + err.Error()
		}
		sni = ""
	}
}

func (mon Monitor) MaintainDB() {
	// Delete unused certificates
	mon.DB.DeleteCertificateBy(`
		NOT EXISTS (SELECT 1 FROM state_certs sc WHERE c.fingerprint = sc.fingerprint)
	`)
	// Delete undiscoverable more
	mon.DB.DeleteStateBy(`
		type=1 AND CAST(julianday('now') - julianday(last_discovery) AS integer) >= 1
	`)
}
