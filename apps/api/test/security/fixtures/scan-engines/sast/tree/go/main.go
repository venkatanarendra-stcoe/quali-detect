package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

var password = "correct-horse-battery"

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	id := r.URL.Query().Get("id")
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))
	exec.Command("sh", "-c", "ls "+id).Run()
	h := md5.New()
	_ = h
	f, _ := os.Open(r.URL.Query().Get("file"))
	_ = f
}

func main() {}
