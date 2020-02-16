package monitor

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DBStateRow struct {
	ID          int
	Host        string    `json:"host"`
	SNI         string    `json:"sni"`
	Valid       int       `json:"valid"`
	Description string    `json:"description"`
	TS          time.Time `json:"ts"`
}

type DBCertRow struct {
	ID                int64
	Fingerprint       string    `json:"fingerprint"`
	IssuerFingerprint string    `json:"issuerFingerprint"`
	CommonName        string    `json:"commonName"`
	Domains           []string  `json:"domains"`
	NotAfter          time.Time `json:"notAfter"`
	NotBefore         time.Time `json:"notBefore"`
	Expired           int       `json:"expired"`
}

type DBWrapper interface {
	GetStateIDByHost(host string, sni string) (id int)
	GetStates() []DBStateRow
	InitDB() error
	InsertCert(cert DBCertRow) error
	InsertState(state DBStateRow) error
	UpdateState(state *DBStateRow, certs []DBCertRow) error
	RunWriter()
	SingleWrite(sql string) (ch chan error)
}

type DBWriteTask struct {
	Out chan error
	SQL string
}

type dbwrapper struct {
	*sql.DB
	Writer chan DBWriteTask
}

var (
	UnexpectedState = errors.New("Unexpected state")
)

func (dbw *dbwrapper) RunWriter() {
	go func() {
		for {
			select {
			case task := <-dbw.Writer:
				tx, err := dbw.Begin()
				if err != nil {
					log.Println(err)
					task.Out <- err
					continue
				}
				if _, err := tx.Exec(task.SQL); err != nil {
					log.Println(err)
					task.Out <- err
					tx.Rollback()
					continue
				}
				tx.Commit()
				task.Out <- nil
			}
		}
	}()
}

func (dbw *dbwrapper) SingleWrite(sql string) (ch chan error) {
	ch = make(chan error)

	dbw.Writer <- DBWriteTask{
		Out: ch,
		SQL: sql,
	}

	return ch
}

func (mon *Monitor) NewDBWrapper(filename string) (err error) {
	var (
		db *sql.DB
	)
	db, err = sql.Open("sqlite3", filename)
	if err != nil {
		log.Println(err)
		return err
	}
	mon.DB = &dbwrapper{
		db,
		make(chan DBWriteTask),
	}

	mon.DB.RunWriter()
	if err := mon.DB.InitDB(); err != nil {
		return err
	}
	return nil
}

func (dbw *dbwrapper) InitDB() error {
	sql := `
	PRAGMA journal_mode=WAL;
	CREATE TABLE IF NOT EXISTS states(
		id integer not null primary key,
		host text not null,
		sni text,
		ts timestamp DEFAULT NULL,
		valid integer DEFAULT 1,
		description text DEFAULT ''
		);
	CREATE UNIQUE INDEX IF NOT EXISTS states_dx
		ON states (host, sni);
	CREATE TABLE IF NOT EXISTS certs(
		id integer not null primary key,
		fingerprint text not null,
		issuer_fingerprint text,
		common_name text,
		domains text,
		not_after timestamp,
		not_before timestamp			
	);
	CREATE UNIQUE INDEX IF NOT EXISTS certs_dx
		ON certs (fingerprint);
	CREATE TABLE IF NOT EXISTS state_certs(
		id integer not null primary key,
		state_id integer,
		fingerprint text
	);
	`
	_, err := dbw.Exec(sql)
	if err != nil {
		log.Println(err)
	}
	return nil
}

func (dbw *dbwrapper) InsertCert(cert DBCertRow) error {

	sql := fmt.Sprintf(`
		INSERT INTO certs(
			fingerprint, issuer_fingerprint, common_name, domains,
			not_after, not_before
		) 
		SELECT '%s', '%s', '%s', '%s', '%s', '%s'
		WHERE  NOT EXISTS (SELECT 1 FROM certs WHERE fingerprint = '%s');
	`, cert.Fingerprint, cert.IssuerFingerprint, cert.CommonName,
		cert.Domains, cert.NotAfter, cert.NotBefore, cert.Fingerprint)

	ch := dbw.SingleWrite(sql)

	return <-ch
}

func (dbw *dbwrapper) InsertState(state DBStateRow) error {

	sql := fmt.Sprintf(`
		INSERT OR IGNORE INTO states(
			host, sni
		) VALUES ('%s', '%s')
		`, state.Host, state.SNI)

	ch := dbw.SingleWrite(sql)

	return <-ch
}

func (dbw *dbwrapper) GetStateIDByHost(host string, sni string) (id int) {
	sql := fmt.Sprintf(`
		SELECT id FROM states WHERE host='%s' and sni='%s'
	`, host, sni)
	rows := dbw.QueryRow(sql)
	if err := rows.Scan(&id); err != nil {
		log.Println(err)
		return 0
	}
	return
}

func (dbw *dbwrapper) GetStates() []DBStateRow {
	var (
		host string
		sni  string
		id   int
	)
	states := make([]DBStateRow, 0, 1)
	sql := fmt.Sprintf(`SELECT id, host, sni FROM states`)
	rows, err := dbw.Query(sql)
	if err != nil {
		log.Println(err)
		return states
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&id, &host, &sni); err != nil {
			log.Println(err)
			break
		}
		states = append(states, DBStateRow{
			ID:   id,
			Host: host,
			SNI:  sni,
		})
	}
	return states
}

func (dbw *dbwrapper) UpdateState(state *DBStateRow, certs []DBCertRow) error {
	for _, cert := range certs {
		if err := dbw.InsertCert(cert); err != nil {
			return nil
		}
	}
	state.TS = time.Now()
	sql := fmt.Sprintf(`
			UPDATE states SET valid=%d, description='%s', ts='%s'
			WHERE host='%s' AND sni='%s';
		`, state.Valid, state.Description, state.TS, state.Host, state.SNI)

	sql = sql + fmt.Sprintf(`
		DELETE FROM state_certs WHERE EXISTS (
			SELECT 1 FROM states WHERE state_certs.state_id=states.id AND host='%s' AND sni='%s'
			);
	`, state.Host, state.SNI)

	for _, cert := range certs {
		sql = sql + fmt.Sprintf(`
			INSERT INTO state_certs(state_id, fingerprint) 
			SELECT id, '%s' FROM states WHERE host='%s' AND sni='%s';
		`, cert.Fingerprint, state.Host, state.SNI)
	}
	ch := dbw.SingleWrite(sql)

	return <-ch
}
