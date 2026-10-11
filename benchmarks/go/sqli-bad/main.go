package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

var db *sql.DB

// Request data concatenated into SQL.
func searchUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, email FROM users WHERE name = '" + name + "'")
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	json.NewEncoder(w).Encode(rows)
}
