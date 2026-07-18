package locale

import (
	"embed"
	"encoding/json"
	"os"
	"strings"
	"sync"
)

//go:embed *.json
var localeFS embed.FS

var (
	global   *Locale
	globalMu sync.RWMutex
)

type Locale struct {
	Code string
	data map[string]string
}

func Get() *Locale {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if global == nil {
		global = mustLoad("en")
	}
	return global
}

func Set(code string) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = mustLoad(code)
}

func T(key string) string {
	return Get().T(key)
}

func mustLoad(code string) *Locale {
	code = strings.ToLower(code)
	if code != "en" && code != "my" {
		code = "en"
	}

	data, err := localeFS.ReadFile(code + ".json")
	if err != nil {
		return &Locale{Code: "en", data: map[string]string{}}
	}

	var entries map[string]string
	if err := json.Unmarshal(data, &entries); err != nil {
		return &Locale{Code: "en", data: map[string]string{}}
	}

	return &Locale{Code: code, data: entries}
}

func (l *Locale) T(key string) string {
	if v, ok := l.data[key]; ok && v != "" {
		return v
	}
	return key
}

func Detect() string {
	lang := os.Getenv("LANG")
	if lang == "" {
		lang = os.Getenv("LC_ALL")
	}
	if lang == "" {
		lang = os.Getenv("LC_MESSAGES")
	}

	lang = strings.ToLower(lang)
	if strings.Contains(lang, "my_") || strings.Contains(lang, "my-") || strings.HasPrefix(lang, "my") {
		return "my"
	}
	return "en"
}

func init() {
	Set(Detect())
}
