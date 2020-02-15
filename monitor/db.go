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
	ID          int64
	Host        string    `json:"host"`
	SNI         string    `json:"sni"`
	Valid       bool      `json:"valid"`
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
	InitDB() error
	InsertCert(cert DBCertRow) error
	insertStateCert(tx *sql.Tx, stateID int, fingerprint string) error
	deleteStateCerts(tx *sql.Tx, stateID int) error
	updateState(tx *sql.Tx, state *DBStateRow) error
	UpdateState(state *DBStateRow, certs []DBCertRow) error
	GetStateIDByHost(host string, sni string) (id int)
}

type dbwrapper struct {
	*sql.DB
}

var (
	UnexpectedState = errors.New("Unexpected state")
)

func (mon *Monitor) NewDBWrapper(filename string) (err error) {
	var (
		db *sql.DB
	)
	db, err = sql.Open("sqlite3", filename)
	if err != nil {
		log.Println(err)
		return err
	}
	mon.DB = &dbwrapper{db}

	if err := mon.DB.InitDB(); err != nil {
		return err
	}
	return nil
}

func (dbw *dbwrapper) InitDB() error {
	sql := `
	CREATE TABLE IF NOT EXISTS states(
		id interger not null primary key,
		host text not null,
		sni text,
		ts timestamp,
		valid interger,
		description text
		);
	CREATE UNIQUE INDEX IF NOT EXISTS states_dx
		ON states (host, sni);
	`
	if _, err := dbw.Exec(sql); err != nil {
		return err
	}

	sql = `
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
	`

	if _, err := dbw.Exec(sql); err != nil {
		return err
	}
	sql = `
		CREATE TABLE IF NOT EXISTS state_certs(
			id integer not null primary key,
			state_id integer,
			fingerprint text
		);
	`
	if _, err := dbw.Exec(sql); err != nil {
		return err
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
		`, cert.Fingerprint, cert.IssuerFingerprint, cert.CommonName, cert.Domains, cert.NotAfter, cert.NotBefore,
		cert.Fingerprint)
	if _, err := dbw.Exec(sql); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (dbw *dbwrapper) updateState(tx *sql.Tx, state *DBStateRow) error {

	stmt, err := tx.Prepare(`
		REPLACE INTO states(host, sni, valid, description, ts)
		VALUES (?, ?, ?, ?, ?);
	`)
	if err != nil {
		log.Println(err)
		return err
	}
	defer stmt.Close()

	state.TS = time.Now()
	if _, err := stmt.Exec(state.Host, state.SNI, state.Valid, state.Description, state.TS); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (dbw *dbwrapper) GetStateIDByHost(host string, sni string) (id int) {
	sql := fmt.Sprintf(`
		SELECT id FROM state WHERE host='%s' and sni='%s'
	`, host, sni)
	rows := dbw.QueryRow(sql)
	if err := rows.Scan(&id); err != nil {
		return 0
	}
	return
}

func (dbw *dbwrapper) deleteStateCerts(tx *sql.Tx, stateID int) error {
	stmt, err := tx.Prepare(`DELETE FROM state_certs WHERE state_id=%d`)
	if err != nil {
		log.Println(err)
		return err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(stateID); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (dbw *dbwrapper) insertStateCert(tx *sql.Tx, stateID int, fingerprint string) error {
	stmt, err := tx.Prepare(`
		INSERT INTO state_certs(state_id, fingerprint) 
		VALUE (?, ?)
	`)
	if err != nil {
		log.Println(err)
		return err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(stateID, fingerprint); err != nil {
		log.Println(err)
		return err
	}
	return nil

}

func (dbw *dbwrapper) UpdateState(state *DBStateRow, certs []DBCertRow) error {
	tx, err := dbw.Begin()
	if err != nil {
		log.Println(err)
		return err
	}
	if err := dbw.updateState(tx, state); err != nil {
		tx.Rollback()
		return nil
	}

	stateID := dbw.GetStateIDByHost(state.Host, state.SNI)
	if stateID == 0 {
		tx.Rollback()
		log.Println("Unexpected state")
		return UnexpectedState
	}

	if err := dbw.deleteStateCerts(tx, stateID); err != nil {
		tx.Rollback()
		return err
	}
	for _, cert := range certs {
		if err := dbw.InsertCert(cert); err != nil {
			return nil
		}
		if err := dbw.insertStateCert(tx, stateID, cert.Fingerprint); err != nil {
			return nil
		}
	}
	tx.Commit()

	return nil
}
