cmd := exec.Command("sh", "-c", userCmd)
cmd := exec.Command("git", "log")
q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
h := md5.New()
resp, err := http.Get(r.FormValue("u"))
resp, err := http.Get("https://api.example.com")
resp, err := http.Get(url)
