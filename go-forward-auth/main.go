package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)
type Config struct {
	ApiURL        string
	AppID         string
	AppKey        string
	CookieName    string
	CookieDomain  string
	SessionSecret string
	Listen        string
	DefaultType   string
	DefaultTypes  []string
	LoginOptions  []LoginOption
}

type stateRecord struct {
	rd  string
	typ string
}

type StateStore struct {
	mu sync.Mutex
	m  map[string]stateRecord
}

func (s *StateStore) Set(state, rd, typ string) {
	s.mu.Lock()
	s.m[state] = stateRecord{rd: rd, typ: typ}
	s.mu.Unlock()
}

func (s *StateStore) Pop(state string) (stateRecord, bool) {
	s.mu.Lock()
	rec, ok := s.m[state]
	if ok {
		delete(s.m, state)
	}
	s.mu.Unlock()
	return rec, ok
}

var (
	cfg    Config
	states = &StateStore{m: make(map[string]stateRecord)}
)
type Claims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Email    string `json:"email,omitempty"`
	Exp      int64  `json:"exp"`
}

func signToken(c Claims) (string, error) {
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, []byte(cfg.SessionSecret))
	mac.Write(b)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyToken(tok string) (*Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return nil, errors.New("bad token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(cfg.SessionSecret))
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, errors.New("invalid signature")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, err
	}
	if time.Now().Unix() > c.Exp {
		return nil, errors.New("expired")
	}
	return &c, nil
}

func randState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func forwardedProto(r *http.Request) string {
	p := r.Header.Get("X-Forwarded-Proto")
	if p == "" {
		p = "https"
	}
	return p
}

func buildCallbackURL(r *http.Request) string {
	return fmt.Sprintf("%s://%s/_june_auth_callback", forwardedProto(r), r.Host)
}

func sanitizeRD(r *http.Request, rd string) string {
	if rd == "" {
		return fmt.Sprintf("%s://%s/", forwardedProto(r), r.Host)
	}
	u, err := url.Parse(rd)
	if err != nil {
		return "/"
	}
	if u.Host != "" && u.Host != r.Host {
		return "/"
	}
	return rd
}
func callLogin(loginType, state, callback string) (string, error) {
	q := url.Values{}
	q.Set("act", "login")
	q.Set("appid", cfg.AppID)
	q.Set("appkey", cfg.AppKey)
	q.Set("type", loginType)
	q.Set("redirect_uri", callback)
	q.Set("state", state)
	resp, err := http.Get(cfg.ApiURL + "connect.php?" + q.Encode())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var res struct {
		Code int    `json:"code"`
		Url  string `json:"url"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	if res.Code != 0 || res.Url == "" {
		return "", fmt.Errorf("login fail: %s", res.Msg)
	}
	return res.Url, nil
}

func callCallback(code string) (map[string]any, error) {
	q := url.Values{}
	q.Set("act", "callback")
	q.Set("appid", cfg.AppID)
	q.Set("appkey", cfg.AppKey)
	q.Set("code", code)
	resp, err := http.Get(cfg.ApiURL + "connect.php?" + q.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	if v, ok := m["code"].(float64); !ok || int(v) != 0 {
		return nil, fmt.Errorf("callback fail: %v", m["msg"])
	}
	return m, nil
}
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cfg.CookieName)
	if err != nil || c.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, err := verifyToken(c.Value)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := claims.Name
	if user == "" {
		user = claims.Sub
	}
	w.Header().Set("X-Auth-User", user)
	w.Header().Set("X-Auth-Email", claims.Email)
	w.Header().Set("X-Auth-Id", claims.Sub)
	w.WriteHeader(http.StatusOK)
}

func startHandler(w http.ResponseWriter, r *http.Request) {
	loginType := r.URL.Query().Get("type")
	rd := sanitizeRD(r, r.URL.Query().Get("rd"))
	callback := buildCallbackURL(r)

	var candidates []string
	if loginType != "" {
		candidates = []string{loginType}
	} else if len(cfg.DefaultTypes) > 0 {
		candidates = cfg.DefaultTypes
	} else if cfg.DefaultType != "" {
		candidates = []string{cfg.DefaultType}
	} else {
		candidates = []string{"qq"}
	}

	var lastErr error
	for _, t := range candidates {
		state := randState()
		url, err := callLogin(t, state, callback)
		if err != nil {
			lastErr = err
			continue
		}
		states.Set(state, rd, t)
		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusBadGateway)
	if lastErr != nil {
		fmt.Fprint(w, lastErr.Error())
	} else {
		fmt.Fprint(w, "no available login type")
	}
}
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	rec, ok := states.Pop(state)
	if !ok || code == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "invalid state or code")
		return
	}
	data, err := callCallback(code)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, err.Error())
		return
	}
	sub, _ := data["social_uid"].(string)
	name, _ := data["nickname"].(string)
	email, _ := data["email"].(string)
	claims := Claims{
		Iss:      "june-forward-auth",
		Sub:      sub,
		Name:     name,
		Provider: rec.typ,
		Email:    email,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	}
	tok, err := signToken(claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
		return
	}
	cookie := &http.Cookie{
		Name:     cfg.CookieName,
		Value:    tok,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		HttpOnly: true,
		Secure:   forwardedProto(r) == "https",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, rec.rd, http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRD(r, r.URL.Query().Get("rd"))
	exp := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cfg.CookieDomain,
		HttpOnly: true,
		Expires:  exp,
		MaxAge:   -1,
	})
	http.Redirect(w, r, rd, http.StatusFound)
}
func envOrDefault(k, def string) string {
	v := os.Getenv(k)
	if v == "" { return def }
	return v
}

func splitCSV(s string) []string {
	if s == "" { return nil }
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" { out = append(out, t) }
	}
	return out
}

func normalizeAPI(urlStr string) string {
	if !strings.HasSuffix(urlStr, "/") {
		return urlStr + "/"
	}
	return urlStr
}

func main() {
	cfg = Config{
		ApiURL:        normalizeAPI(envOrDefault("JUNE_API_URL", "https://u.june.ink/")),
		AppID:         os.Getenv("JUNE_APP_ID"),
		AppKey:        os.Getenv("JUNE_APP_KEY"),
		CookieName:    envOrDefault("JUNE_COOKIE_NAME", "june_session"),
		CookieDomain:  os.Getenv("JUNE_COOKIE_DOMAIN"),
		SessionSecret: os.Getenv("JUNE_SESSION_SECRET"),
		Listen:        envOrDefault("LISTEN_ADDR", ":4181"),
		DefaultType:   envOrDefault("JUNE_DEFAULT_TYPE", "qq"),
		DefaultTypes:  splitCSV(os.Getenv("JUNE_DEFAULT_TYPES")),
	}
	// 解析用户可选登录方式（key:Label, 逗号分隔）
	cfg.LoginOptions = parseLoginOptions(os.Getenv("JUNE_LOGIN_OPTIONS"))

	if cfg.AppID == "" || cfg.AppKey == "" || cfg.SessionSecret == "" {
		log.Fatal("env JUNE_APP_ID, JUNE_APP_KEY, JUNE_SESSION_SECRET 必填")
	}

	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/start", startHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/login", loginHandler)
	log.Printf("Forward-Auth 启动: %s", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, nil))
}
type LoginOption struct {
	Key   string
	Label string
}

func parseLoginOptions(s string) []LoginOption {
	opts := []LoginOption{}
	if s == "" {
		return opts
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, ":") {
			kv := strings.SplitN(p, ":", 2)
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			if k != "" {
				if v == "" { v = k }
				opts = append(opts, LoginOption{Key: k, Label: v})
			}
		} else {
			opts = append(opts, LoginOption{Key: p, Label: p})
		}
	}
	return opts
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRD(r, r.URL.Query().Get("rd"))
	opts := cfg.LoginOptions
	if len(opts) == 0 {
		// 回退：使用多候选或单默认值构造选项
		if len(cfg.DefaultTypes) > 0 {
			for _, t := range cfg.DefaultTypes {
				opts = append(opts, LoginOption{Key: t, Label: t})
			}
		} else if cfg.DefaultType != "" {
			opts = []LoginOption{{Key: cfg.DefaultType, Label: cfg.DefaultType}}
		}
	}
	if len(opts) == 0 {
		opts = []LoginOption{{Key: "qq", Label: "qq"}}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>选择登录方式</title><style>body{font-family:sans-serif;margin:40px}a.btn{display:block;margin:10px 0;padding:12px 16px;background:#0d6efd;color:#fff;text-decoration:none;border-radius:6px;width:260px;text-align:center}a.btn:hover{opacity:.9}</style></head><body>")
	io.WriteString(w, "<h2>请选择登录方式</h2>")
	qrd := url.QueryEscape(rd)
	for _, o := range opts {
		link := "/_june_auth_start?type=" + url.QueryEscape(o.Key) + "&rd=" + qrd
		fmt.Fprintf(w, "<a class=\"btn\" href=\"%s\">%s</a>", link, o.Label)
	}
	io.WriteString(w, "</body></html>")
}
