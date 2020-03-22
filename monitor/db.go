package monitor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

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

// DBStateRow represents table `states` row
type DBStateRow struct {
	Certificates  []DBCertRow `json:"certificates"`
	Description   string      `json:"description"`
	Host          string      `json:"host"`
	ID            int         `json:"id"`
	LastDiscovery time.Time   `json:"lasDiscovery"`
	SNI           string      `json:"sni"`
	TS            time.Time   `json:"ts"`
	Type          int         `json:"type"`
	Valid         int         `json:"valid"`
}

// DBCertRow represents table `certs` row
type DBCertRow struct {
	CommonName  string    `json:"commonName"`
	Domains     string    `json:"domains"`
	Expired     int       `json:"expired"`
	Fingerprint string    `json:"fingerprint"`
	ID          int       `json:"id"`
	IssuerHash  string    `json:"issuerHash"`
	NotAfter    time.Time `json:"notAfter"`
	NotBefore   time.Time `json:"notBefore"`
	SubjectHash string    `json:"subjectHash"`
}

type dbwrapper struct {
	*sql.DB
	Writer chan DBWriteTask
}

// DBWrapper represents application database
type DBWrapper interface {
	Close()
	InitDB() error
	RunWriter(ctx context.Context)
	SingleWrite(sql string) (ch chan error)

	DeleteCertificateBy(where string) error
	DeleteExclude(host string, sni string) error
	DeleteStateBy(where string) error
	GetCertificateByID(id int) *DBCertRow
	GetCertificatesBy(where string) []DBCertRow
	GetCertificatesByExpire(expire int) []DBCertRow
	GetStateCertsBy(where string) []DBStateRow
	GetStatesBy(where string) []DBStateRow
	GetStatesByExpire(expire int) []DBStateRow
	GetStateByID(id int) *DBStateRow
	GetStatesByValid(valid int) []DBStateRow
	InsertCert(cert DBCertRow) error
	InsertExclude(host string, sni string) error
	InsertState(state DBStateRow) error
	UpdateState(state *DBStateRow) error
	UpdateStateLastDiscovery(state *DBStateRow) error
}

// DBWriteTask represents database writing task
//	Out - writing result
//	SQL - query
type DBWriteTask struct {
	Out chan error
	SQL string
}

func timestampToSQLite(ts time.Time) string {
	return ts.Format(time.RFC3339)
}

func OpenDB(filename string) *dbwrapper {
	var dbw *dbwrapper

	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		log.Println(err)
		return nil
	}
	dbw = &dbwrapper{
		db,
		make(chan DBWriteTask),
	}

	if err := dbw.InitDB(); err != nil {
		db.Close()
		log.Panicln(err)
		return nil
	}
	log.Printf("Database %s is opened successfully\n", filename)
	return dbw
}

func (dbw *dbwrapper) RunWriter(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
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

func (dbw *dbwrapper) Close() {
	log.Println("Database is closed")
	dbw.DB.Close()
}

func (dbw *dbwrapper) InitDB() error {
	sql := `
	PRAGMA journal_mode=WAL;
	CREATE TABLE IF NOT EXISTS states(
		id integer not null primary key,
		host text not null,
		sni text,
		last_discovery timestamp,
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
		issuer_hash text,
		subject_hash text not null,
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
	CREATE TABLE IF NOT EXISTS excludes (
		id integer not null primary key,
		host text not null,
		sni text
	);
	CREATE VIEW IF NOT EXISTS vCerts AS
		SELECT certs.*, (strftime('%s', not_after) - strftime('%s', 'now')) / (24 * 3600) AS expired
		FROM certs;
	CREATE VIEW IF NOT EXISTS vStates AS
		SELECT 
			s.id AS state_id, host, sni, type, valid, description,
			c.id as cert_id, c.fingerprint, issuer_hash, subject_hash, common_name, domains, not_after, not_before, expired
		FROM states AS s
			INNER JOIN state_certs AS sc ON s.id = sc.state_id
			INNER JOIN vCerts AS c ON c.fingerprint = sc.fingerprint;
	`
	_, err := dbw.Exec(sql)
	if err != nil {
		log.Println(err)
	}
	return nil
}

func (dbw *dbwrapper) DeleteCertificateBy(where string) error {
	if len(where) == 0 {
		return errors.New("Condition for a DELETE query is empty")
	}
	sql := fmt.Sprintf(`DELETE FROM certs AS c WHERE %s;`, where)
	ch := dbw.SingleWrite(sql)
	return <-ch
}

func (dbw *dbwrapper) DeleteStateBy(where string) error {
	if len(where) == 0 {
		return errors.New("Condition for a DELETE query is empty")
	}
	sql := fmt.Sprintf(`DELETE FROM states AS s WHERE %s;`, where)
	ch := dbw.SingleWrite(sql)
	return <-ch
}

func (dbw *dbwrapper) DeleteExclude(host string, sni string) error {
	return nil
}

func (dbw *dbwrapper) GetCertificatesBy(where string) []DBCertRow {
	var c DBCertRow
	sql := fmt.Sprintf(`
		SELECT 
			id, fingerprint, subject_hash, issuer_hash, common_name, domains, 
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
		if err := rows.Scan(&c.ID, &c.Fingerprint, &c.SubjectHash, &c.IssuerHash, &c.CommonName,
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

func (dbw *dbwrapper) GetStateCertsBy(where string) []DBStateRow {
	var (
		s DBStateRow
		c DBCertRow
	)
	sql := fmt.Sprintf(`
		SELECT 
		state_id, host, sni, type, valid, description,
		cert_id, fingerprint, subject_hash, issuer_hash, common_name, domains, not_after, not_before, expired
	FROM vStates %s`, where)
	rows, err := dbw.Query(sql)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer rows.Close()

	states := make(map[int]DBStateRow)
	for rows.Next() {
		c = DBCertRow{}
		s = DBStateRow{}
		if err := rows.Scan(
			&s.ID, &s.Host, &s.SNI, &s.Type, &s.Valid, &s.Description,
			&c.ID, &c.Fingerprint, &c.SubjectHash, &c.IssuerHash, &c.CommonName, &c.Domains, &c.NotAfter, &c.NotBefore, &c.Expired); err != nil {
			log.Println(err)
			break
		}
		if state, exists := states[s.ID]; exists {
			state.Certificates = append(state.Certificates, c)
			states[s.ID] = state
		} else {
			s.Certificates = append(s.Certificates, c)
			states[s.ID] = s
		}
	}
	result := make([]DBStateRow, 0, 1)
	for _, v := range states {
		result = append(result, v)
	}

	return result
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

func (dbw *dbwrapper) GetStatesByExpire(expire int) []DBStateRow {
	return dbw.GetStateCertsBy(fmt.Sprintf("WHERE expired < %d", expire))
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

func (dbw *dbwrapper) InsertCert(cert DBCertRow) error {

	sql := fmt.Sprintf(`
		INSERT INTO certs(
			fingerprint, subject_hash, issuer_hash, common_name, domains,
			not_after, not_before
		) 
		SELECT '%s', '%s', '%s', '%s', '%s', '%s', '%s'
		WHERE  NOT EXISTS (SELECT 1 FROM certs WHERE fingerprint = '%s');
	`, cert.Fingerprint, cert.SubjectHash, cert.IssuerHash, cert.CommonName,
		cert.Domains, timestampToSQLite(cert.NotAfter), timestampToSQLite(cert.NotBefore), cert.Fingerprint)

	ch := dbw.SingleWrite(sql)

	return <-ch
}

func (dbw *dbwrapper) InsertExclude(host string, sni string) error {
	return nil
}

func (dbw *dbwrapper) InsertState(state DBStateRow) error {

	sql := fmt.Sprintf(`
		INSERT OR IGNORE INTO states(
			host, sni, type 
		) VALUES ('%s', '%s', %d);		
		`, state.Host, state.SNI, state.Type)

	ch := dbw.SingleWrite(sql)
	if err := <-ch; err != nil {
		return err
	}
	if state.Type == DiscoveryState {
		return dbw.UpdateStateLastDiscovery(&state)
	}

	return nil
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

func (dbw *dbwrapper) UpdateStateLastDiscovery(state *DBStateRow) error {
	state.LastDiscovery = time.Now()
	sql := fmt.Sprintf(`
		UPDATE OR IGNORE states
			SET last_discovery = '%s'
			WHERE host = '%s' AND sni = '%s'
	`, timestampToSQLite(state.LastDiscovery), state.Host, state.SNI)

	ch := dbw.SingleWrite(sql)

	return <-ch
}
