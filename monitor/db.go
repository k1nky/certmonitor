package monitor

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DBStateRow represents table `states` row
type DBStateRow struct {
	ID           int       `json:"id"`
	Host         string    `json:"host"`
	SNI          string    `json:"sni"`
	Valid        int       `json:"valid"`
	Description  string    `json:"description"`
	TS           time.Time `json:"ts"`
	Type         int       `json:"type"`
	Certificates []DBCertRow
}

// DBCertRow represents table `certs` row
type DBCertRow struct {
	ID                int
	Fingerprint       string    `json:"fingerprint"`
	IssuerFingerprint string    `json:"issuerFingerprint"`
	CommonName        string    `json:"commonName"`
	Domains           string    `json:"domains"`
	NotAfter          time.Time `json:"notAfter"`
	NotBefore         time.Time `json:"notBefore"`
	Expired           int       `json:"expired"`
}

type dbwrapper struct {
	*sql.DB
	Writer chan DBWriteTask
}

// DBWrapper represents application database
type DBWrapper interface {
	GetCertificateByID(id int) *DBCertRow
	GetCertificatesBy(where string) []DBCertRow
	GetCertificatesByExpire(expire int) []DBCertRow
	GetStatesBy(where string) []DBStateRow
	GetStateByID(id int) *DBStateRow
	GetStatesByValid(valid int) []DBStateRow
	InitDB() error
	InsertCert(cert DBCertRow) error
	InsertState(state DBStateRow) error
	UpdateState(state *DBStateRow) error
	RunWriter()
	SingleWrite(sql string) (ch chan error)
}

// DBWriteTask represents database writing task
//	Out - writing result
//	SQL - query
type DBWriteTask struct {
	Out chan error
	SQL string
}

const (
	// InvalidState mean that host has invalid TLS state
	InvalidState = 0
	// ValidState mean that host has valid TLS state
	ValidState = 1
	// UnknownState mean that failed to check TLS state.
	//	For example, host is unreachable.
	UnknownState = -1
	// CustomState defines host which is added via API
	CustomState = 0
	// DiscoveryState defines DNS discovered host
	DiscoveryState = 1
)

func timestampToSQLite(ts time.Time) string {
	return ts.Format(time.RFC3339)
}

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
					log.Println(err, task.SQL)
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
		ts timestamp DEFAULT CURRENT_TIMESTAMP,
		valid integer DEFAULT -1,
		description text DEFAULT '',
		type integer DEFAULT 0
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
	CREATE VIEW IF NOT EXISTS vCerts AS
		SELECT certs.*, (strftime('%s', not_after) - strftime('%s', 'now')) / (24 * 3600) AS expired
		FROM certs;
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
		cert.Domains, timestampToSQLite(cert.NotAfter), timestampToSQLite(cert.NotBefore), cert.Fingerprint)

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

func (dbw *dbwrapper) GetCertificatesBy(where string) []DBCertRow {
	var c DBCertRow
	sql := fmt.Sprintf(`
		SELECT 
			id, fingerprint, issuer_fingerprint, common_name, domains, 
			not_after, not_before, expired
		FROM vCerts %s
	`, where)

	certs := make([]DBCertRow, 0, 1)
	rows, err := dbw.Query(sql)
	if err != nil {
		log.Println(err)
		return certs
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&c.ID, &c.Fingerprint, &c.IssuerFingerprint, &c.CommonName,
			&c.Domains, &c.NotAfter, &c.NotBefore, &c.Expired); err != nil {
			log.Println(err)
			break
		}
		certs = append(certs, c)
	}
	return certs

}

func (dbw *dbwrapper) GetCertificateByID(id int) *DBCertRow {
	certs := dbw.GetCertificatesBy(fmt.Sprintf("WHERE ID=%d", id))
	if len(certs) == 0 {
		return nil
	}
	return &(certs[0])
}

func (dbw *dbwrapper) GetCertificatesByExpire(expired int) []DBCertRow {
	return dbw.GetCertificatesBy(fmt.Sprintf("WHERE expired < %d", expired))
}

func (dbw *dbwrapper) GetStatesBy(where string) []DBStateRow {
	var s DBStateRow

	sql := fmt.Sprintf(`
		SELECT 
			id, host, sni, valid, description, ts, type
		FROM states %s`, where)
	rows, err := dbw.Query(sql)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer rows.Close()
	states := make([]DBStateRow, 0, 1)
	for rows.Next() {
		if err := rows.Scan(&s.ID, &s.Host, &s.SNI, &s.Valid, &s.Description,
			&s.TS, &s.Type); err != nil {
			log.Println(err)
			break
		}
		states = append(states, s)
	}
	return states
}

func (dbw *dbwrapper) GetStatesByValid(valid int) []DBStateRow {
	return dbw.GetStatesBy(fmt.Sprintf("WHERE valid=%d", valid))
}

func (dbw *dbwrapper) GetStateByID(id int) *DBStateRow {
	states := dbw.GetStatesBy(fmt.Sprintf("WHERE id=%d", id))
	if len(states) == 0 {
		return nil
	}
	return &(states[0])
}

func (dbw *dbwrapper) UpdateState(state *DBStateRow) error {
	for _, cert := range state.Certificates {
		if err := dbw.InsertCert(cert); err != nil {
			return nil
		}
	}
	state.TS = time.Now()
	sql := fmt.Sprintf(`
			UPDATE states SET valid=%d, description='%s', ts='%s'
			WHERE host='%s' AND sni='%s';
		`, state.Valid, state.Description, timestampToSQLite(state.TS), state.Host, state.SNI)

	sql = sql + fmt.Sprintf(`
			DELETE FROM state_certs WHERE EXISTS (
				SELECT 1 FROM states WHERE state_certs.state_id=states.id AND host='%s' AND sni='%s'
			);
	`, state.Host, state.SNI)

	for _, cert := range state.Certificates {
		sql = sql + fmt.Sprintf(`
			INSERT INTO state_certs(state_id, fingerprint) 
			SELECT id, '%s' FROM states WHERE host='%s' AND sni='%s';
		`, cert.Fingerprint, state.Host, state.SNI)
	}
	ch := dbw.SingleWrite(sql)

	return <-ch
}
