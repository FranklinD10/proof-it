//! Each Go detector must fire on the vulnerable snippet and stay silent on the safe one.

fn rules(code: &str) -> Vec<String> {
    let a = proof_it_lang_go::analyze("t.go", code).expect("parse");
    a.findings.into_iter().map(|f| f.rule_id).collect()
}

fn case(rule: &str, bad: &str, good: &str) {
    let b = rules(bad);
    assert!(b.iter().any(|r| r == rule), "{rule} should fire on:\n{bad}\nfound: {b:?}");
    let g = rules(good);
    assert!(!g.iter().any(|r| r == rule), "{rule} should NOT fire on:\n{good}\nfound: {g:?}");
}

fn http(body: &str) -> String {
    format!("package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {{\n{body}\n}}\n")
}

fn gin(body: &str) -> String {
    format!("package main\n\nimport \"github.com/gin-gonic/gin\"\n\nfunc h(c *gin.Context) {{\n{body}\n}}\n")
}

#[test]
fn sql_injection() {
    case(
        "SEC-SQLI",
        &http(
            r#"id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM users WHERE id = '" + id + "'")
	_ = rows"#,
        ),
        &http(
            r#"id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
	_ = rows"#,
        ),
    );
    // Sprintf into a variable, gin source, gorm Raw.
    case(
        "SEC-SQLI",
        &gin(r#"name := c.Query("name")
	q := fmt.Sprintf("SELECT * FROM t WHERE name = '%s'", name)
	db.Raw(q).Scan(&out)"#),
        &gin(r#"name := c.Query("name")
	db.Raw("SELECT * FROM t WHERE name = ?", name).Scan(&out)"#),
    );
    // Bound request body (ShouldBindJSON) into a gorm Where with concatenation.
    case(
        "SEC-SQLI",
        &gin(r#"var in struct{ Name string }
	c.ShouldBindJSON(&in)
	db.Where("name = '" + in.Name + "'").Find(&users)"#),
        &gin(r#"var in struct{ Name string }
	c.ShouldBindJSON(&in)
	db.Where("name = ?", in.Name).Find(&users)"#),
    );
}

#[test]
fn numeric_conversion_sanitizes() {
    case(
        "SEC-SQLI",
        &http(
            r#"id := r.FormValue("id")
	db.Exec("DELETE FROM t WHERE id = " + id)"#,
        ),
        &http(
            r#"id, _ := strconv.Atoi(r.FormValue("id"))
	db.Exec("DELETE FROM t WHERE id = " + strconv.Itoa(id))"#,
        ),
    );
}

#[test]
fn command_injection() {
    case(
        "SEC-CMDI",
        &http(
            r#"host := r.URL.Query().Get("host")
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()"#,
        ),
        &http(r#"exec.Command("sh", "-c", "uptime").Run()"#),
    );
}

#[test]
fn path_traversal() {
    case(
        "SEC-PATH-TRAVERSAL",
        &http(
            r#"name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)"#,
        ),
        &http(
            r#"name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", filepath.Base(name)))
	w.Write(data)"#,
        ),
    );
}

#[test]
fn ssrf_and_open_redirect() {
    case(
        "SEC-SSRF",
        &http(
            r#"resp, _ := http.Get(r.URL.Query().Get("url"))
	_ = resp"#,
        ),
        &http(
            r#"resp, _ := http.Get("https://status.example.com/health")
	_ = resp"#,
        ),
    );
    case(
        "SEC-OPEN-REDIRECT",
        &http(r#"http.Redirect(w, r, r.FormValue("next"), http.StatusFound)"#),
        &http(r#"http.Redirect(w, r, "/home", http.StatusFound)"#),
    );
}

#[test]
fn reflected_xss() {
    case(
        "SEC-XSS",
        &http(
            r#"name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)"#,
        ),
        &http(
            r#"name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))"#,
        ),
    );
}

#[test]
fn tls_and_weak_hash_and_random() {
    case(
        "SEC-TLS-DISABLED",
        "package main\n\nvar c = &tls.Config{InsecureSkipVerify: true}\n",
        "package main\n\nvar c = &tls.Config{MinVersion: tls.VersionTLS12}\n",
    );
    case(
        "SEC-WEAK-HASH",
        "package main\n\nfunc hashPassword(password string) [16]byte {\n\treturn md5.Sum([]byte(password))\n}\n",
        "package main\n\nfunc etag(body []byte) [16]byte {\n\treturn md5.Sum(body)\n}\n",
    );
    case(
        "SEC-INSECURE-RANDOM",
        "package main\n\nimport \"math/rand\"\n\nfunc resetToken() int {\n\ttoken := rand.Intn(1000000)\n\treturn token\n}\n",
        "package main\n\nimport \"math/rand\"\n\nfunc shuffle(xs []int) {\n\tn := rand.Intn(len(xs))\n\t_ = n\n}\n",
    );
}

#[test]
fn sanitizers_are_judged_by_their_code() {
    case(
        "SEC-SQLI",
        "package main\n\nfunc sanitize(s string) string { return s }\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tq := sanitize(r.FormValue(\"q\"))\n\tdb.Query(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n}\n",
        "package main\n\nfunc sanitize(s string) string { return strings.Map(keepAlnum, s) }\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tq := sanitize(r.FormValue(\"q\"))\n\tdb.Query(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n}\n",
    );
}

#[test]
fn parse_errors_are_reported() {
    assert!(proof_it_lang_go::analyze("t.go", "package main\nfunc h( {\n").is_err());
}

#[test]
fn dynamic_sql_with_context_argument() {
    // Built from placeholders and passed via a variable with a context first: reviewed, not injection.
    let code = http(
        r#"conds := []string{"category = $1"}
	q := fmt.Sprintf("SELECT COUNT(*) FROM t %s", "WHERE "+strings.Join(conds, " AND "))
	db.QueryRowContext(r.Context(), q, cat).Scan(&n)"#,
    );
    let r = rules(&code);
    assert!(r.contains(&"SEC-DYNAMIC-SQL".to_owned()) && !r.contains(&"SEC-SQLI".to_owned()), "{r:?}");
    // pgx: context first without a Context suffix; request data in the query.
    case(
        "SEC-SQLI",
        &http(
            r#"q := "SELECT * FROM t WHERE name = '" + r.FormValue("n") + "'"
	pool.QueryRow(ctx, q).Scan(&x)"#,
        ),
        &http(r#"pool.QueryRow(ctx, "SELECT * FROM t WHERE name = $1", r.FormValue("n")).Scan(&x)"#),
    );
}
