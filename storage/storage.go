package storage

import (
	"database/sql"
	"strings"
)

type StorageAdapter struct {
	db *sql.DB
}

func NewStorageAdapter(db *sql.DB) *StorageAdapter {
	return &StorageAdapter{db: db}
}

/**
 * Check if the active connection uses TLS in MySQL.
 */
func (a *StorageAdapter) IsMySQLTlsSecured() bool {
	var name, val string
	row := a.db.QueryRow("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
	err := row.Scan(&name, &val)
	if err != nil {
		return false
	}
	return val != "" && strings.ToLower(val) != "null"
}

/**
 * Check if the active connection uses TLS in PostgreSQL.
 */
func (a *StorageAdapter) IsPostgresTlsSecured() bool {
	var ssl bool
	row := a.db.QueryRow("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
	err := row.Scan(&ssl)
	if err != nil {
		return false
	}
	return ssl
}
