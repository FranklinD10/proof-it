package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

var db *sql.DB

// Parameterised query: the value is a bound argument.
func searchUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.QueryContext(r.Context(), "SELECT id, email FROM users WHERE name = $1", name)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	json.NewEncoder(w).Encode(rows)
}
