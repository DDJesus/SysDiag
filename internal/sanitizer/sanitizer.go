package sanitizer

import (
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/models"
)

var (
	windowsUserPath = regexp.MustCompile(`(?i)([a-z]:\\(?:users|documents and settings)\\)[^\\/:]+`)
	posixUserPath   = regexp.MustCompile(`(?i)(/(?:home|users)/)[^/\\\s]+`)
	rootPath        = regexp.MustCompile(`(?i)(/root)(/|$)`)
	macAddress      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	ipv4Candidate   = `(?:[0-9]{1,3}\.){3}[0-9]{1,3}`
	ipv6Candidate   = `(?:::ffff:` + ipv4Candidate + `|(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{0,4}|` + ipv4Candidate + `))`
	ipCandidate     = regexp.MustCompile(`(?i)(?:\[` + ipv6Candidate + `(?:%[a-z0-9_.-]+)?\]|\[` + ipv4Candidate + `\]|` + ipv6Candidate + `(?:%[a-z0-9_.-]+)?|` + ipv4Candidate + `)`)
)

type identifier struct {
	value   string
	token   string
	pattern *regexp.Regexp
}

// SanitizeReport redacts sensitive identifiers from every string in the report.
// It mutates in place and does not change the report's JSON shape.
func SanitizeReport(report *models.DiagnosticReport) {
	if report == nil {
		return
	}

	var identifiers []identifier
	add := func(value, token string) {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "unknown") || strings.EqualFold(value, "none") {
			return
		}
		if token == "[SERIAL_REDACTED]" && len(value) < 5 {
			return
		}
		for _, existing := range identifiers {
			if strings.EqualFold(existing.value, value) {
				return
			}
		}
		identifiers = append(identifiers, newIdentifier(value, token))
	}

	addHostnameIdentifiers(add, report.Metadata.Hostname)
	if report.Data.System != nil {
		addHostnameIdentifiers(add, report.Data.System.Hostname)
	}
	for _, key := range []string{"USERNAME", "USER"} {
		add(os.Getenv(key), "[USER_REDACTED]")
	}
	for _, key := range []string{"USERDOMAIN", "USERDNSDOMAIN"} {
		add(os.Getenv(key), "[DOMAIN_REDACTED]")
	}
	for _, key := range []string{"HOME", "USERPROFILE"} {
		add(strings.TrimRight(os.Getenv(key), `\/`), "[HOME_REDACTED]")
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(strings.TrimRight(home, `\/`), "[HOME_REDACTED]")
	}
	add(strings.TrimRight(os.Getenv("HOMEDRIVE")+os.Getenv("HOMEPATH"), `\/`), "[HOME_REDACTED]")
	if report.Data.Storage != nil {
		for _, disk := range report.Data.Storage.PhysicalDisks {
			add(disk.SerialNumber, "[SERIAL_REDACTED]")
		}
	}
	if report.Data.Network != nil {
		for _, adapter := range report.Data.Network.Adapters {
			add(adapter.MACAddress, "[MAC_REDACTED]")
		}
	}
	if report.Data.Services != nil {
		for _, service := range append(append([]models.ServiceInfo(nil), report.Data.Services.Services...), report.Data.Services.FailedAutoStart...) {
			addServiceAccountIdentifiers(add, service.Account)
		}
	}

	clean := func(value string) string { return sanitizeString(value, identifiers) }
	sanitizeStrings(reflect.ValueOf(report), clean)
	if report.Metadata.Hostname != "" {
		report.Metadata.Hostname = "REDACTED-HOST"
	}
	if report.Data.System != nil && report.Data.System.Hostname != "" {
		report.Data.System.Hostname = "REDACTED-HOST"
	}
}

func addServiceAccountIdentifiers(add func(string, string), account string) {
	if account == "" || isBuiltInAccount(account) {
		return
	}
	add(account, "[ACCOUNT_REDACTED]")
	if slash := strings.LastIndexByte(account, '\\'); slash >= 0 {
		add(account[:slash], "[DOMAIN_REDACTED]")
		add(account[slash+1:], "[USER_REDACTED]")
	} else if at := strings.LastIndexByte(account, '@'); at > 0 {
		add(account[:at], "[USER_REDACTED]")
		add(account[at+1:], "[DOMAIN_REDACTED]")
	}
}

func isBuiltInAccount(account string) bool {
	switch strings.ToLower(account) {
	case "system", "localsystem", "nt authority\\system", "localservice", "networkservice",
		"nt authority\\local service", "nt authority\\network service", "root", "nobody":
		return true
	default:
		return false
	}
}

func addHostnameIdentifiers(add func(string, string), hostname string) {
	add(hostname, "REDACTED-HOST")
	if dot := strings.IndexByte(hostname, '.'); dot > 0 && dot < len(hostname)-1 {
		add(hostname[dot+1:], "[DOMAIN_REDACTED]")
	}
}

// SanitizeText applies standard identifier and path redactions to a string,
// plus any caller-known hostnames that may appear in displayed artifact paths.
func SanitizeText(value string, knownHostnames ...string) string {
	var identifiers []identifier
	for _, hostname := range knownHostnames {
		if hostname != "" && hostname != "UNKNOWN-HOST" && hostname != "REDACTED-HOST" {
			addHostnameIdentifiers(func(value, token string) {
				if value != "" {
					identifiers = append(identifiers, newIdentifier(value, token))
				}
			}, hostname)
		}
	}
	for _, key := range []string{"USERNAME", "USER"} {
		user := strings.TrimSpace(os.Getenv(key))
		if user != "" {
			identifiers = append(identifiers, newIdentifier(user, "[USER_REDACTED]"))
		}
	}
	for _, key := range []string{"USERDOMAIN", "USERDNSDOMAIN"} {
		domain := strings.TrimSpace(os.Getenv(key))
		if domain != "" {
			identifiers = append(identifiers, newIdentifier(domain, "[DOMAIN_REDACTED]"))
		}
	}
	for _, key := range []string{"HOME", "USERPROFILE"} {
		home := strings.TrimRight(strings.TrimSpace(os.Getenv(key)), `\/`)
		if home != "" {
			identifiers = append(identifiers, newIdentifier(home, "[HOME_REDACTED]"))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		home = strings.TrimRight(home, `\/`)
		if home != "" {
			identifiers = append(identifiers, newIdentifier(home, "[HOME_REDACTED]"))
		}
	}
	home := strings.TrimRight(os.Getenv("HOMEDRIVE")+os.Getenv("HOMEPATH"), `\/`)
	if home != "" {
		identifiers = append(identifiers, newIdentifier(home, "[HOME_REDACTED]"))
	}
	return sanitizeString(value, identifiers)
}

func sanitizeString(value string, identifiers []identifier) string {
	value = windowsUserPath.ReplaceAllString(value, `${1}[REDACTED]`)
	value = posixUserPath.ReplaceAllString(value, `${1}[REDACTED]`)
	value = rootPath.ReplaceAllString(value, `/home/[REDACTED]${2}`)
	for _, item := range identifiers {
		if item.token == "[SERIAL_REDACTED]" {
			value = item.pattern.ReplaceAllString(value, item.token)
			continue
		}
		value = replaceIdentifier(value, item)
	}
	value = macAddress.ReplaceAllString(value, "[MAC_REDACTED]")
	return redactIPAddresses(value)
}

func newIdentifier(value, token string) identifier {
	item := identifier{value: value, token: token}
	if token == "[SERIAL_REDACTED]" {
		item.pattern = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(value))
	} else {
		item.pattern = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(value))
	}
	return item
}

func replaceIdentifier(text string, item identifier) string {
	matches := item.pattern.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var out strings.Builder
	last := 0
	for _, match := range matches {
		start, end := match[0], match[1]
		if !identifierBoundary(text, start-1) || !identifierBoundary(text, end) {
			continue
		}
		out.WriteString(text[last:start])
		out.WriteString(item.token)
		last = end
	}
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}

func identifierBoundary(text string, index int) bool {
	if index < 0 || index >= len(text) {
		return true
	}
	b := text[index]
	return !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '.')
}

func redactIPAddresses(text string) string {
	matches := ipCandidate.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var out strings.Builder
	last := 0
	for _, match := range matches {
		start, end := match[0], match[1]
		candidate := text[start:end]
		address := strings.TrimPrefix(strings.TrimSuffix(candidate, "]"), "[")
		if zone := strings.LastIndexByte(address, '%'); zone >= 0 {
			address = address[:zone]
		}
		if net.ParseIP(address) == nil || !ipBoundary(text, start-1, candidate, true) || !ipBoundary(text, end, candidate, false) {
			continue
		}
		out.WriteString(text[last:start])
		out.WriteString("[IP_REDACTED]")
		last = end
	}
	if last == 0 {
		return text
	}
	out.WriteString(text[last:])
	return out.String()
}

func ipBoundary(text string, index int, candidate string, before bool) bool {
	if index < 0 || index >= len(text) {
		return true
	}
	b := text[index]
	if isIPTokenByte(b) {
		// A colon can separate an address from surrounding diagnostic text. A
		// colon after IPv4 may also introduce a port; keep the port untouched.
		if b == ':' {
			if before {
				return true
			}
			address := strings.Trim(candidate, "[]")
			if !strings.Contains(address, ":") {
				return true
			}
			for i := index + 1; i < len(text); i++ {
				c := text[i]
				if c < '0' || c > '9' {
					return !isHexByte(c)
				}
			}
			return true
		}
		return false
	}
	return true
}

func isIPTokenByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune(".:/%[]_-", rune(b))
}

func isHexByte(b byte) bool {
	return (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') || (b >= '0' && b <= '9')
}

var timeType = reflect.TypeOf(time.Time{})

func sanitizeStrings(value reflect.Value, clean func(string) string) {
	if !value.IsValid() {
		return
	}
	if value.Type() == timeType {
		return
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() || !value.CanSet() {
			return
		}
		inner := copyValue(value.Elem())
		sanitizeStrings(inner, clean)
		value.Set(inner)
	case reflect.Pointer:
		if !value.IsNil() {
			sanitizeStrings(value.Elem(), clean)
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.CanSet() {
				sanitizeStrings(field, clean)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			sanitizeStrings(value.Index(i), clean)
		}
	case reflect.Map:
		if value.IsNil() {
			return
		}
		keys := value.MapKeys()
		if value.Type().Key().Kind() == reflect.String {
			sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
			value.Set(sanitizeStringKeyMap(value, keys, clean))
			return
		}
		for _, key := range keys {
			updated := copyValue(value.MapIndex(key))
			sanitizeStrings(updated, clean)
			value.SetMapIndex(key, updated)
		}
	case reflect.String:
		if value.CanSet() {
			value.SetString(clean(value.String()))
		}
	}
}

func sanitizeStringKeyMap(value reflect.Value, keys []reflect.Value, clean func(string) string) reflect.Value {
	// Safe keys keep their original names. Changed keys are processed in sorted
	// source-key order, and collisions receive increasing explicit suffixes.
	type entry struct {
		key     reflect.Value
		clean   string
		value   reflect.Value
		changed bool
	}
	entries := make([]entry, 0, len(keys))
	reserved := make(map[string]bool, len(keys))
	for _, key := range keys {
		cleanKey := clean(key.String())
		item := entry{key: key, clean: cleanKey, value: value.MapIndex(key), changed: cleanKey != key.String()}
		entries = append(entries, item)
		if !item.changed {
			reserved[cleanKey] = true
		}
	}
	result := reflect.MakeMapWithSize(value.Type(), len(entries))
	used := make(map[string]bool, len(entries))
	for _, item := range entries {
		key := item.clean
		if item.changed && (reserved[key] || used[key]) {
			base := key
			for suffix := 2; reserved[key] || used[key]; suffix++ {
				key = base + " [redacted key " + strconv.Itoa(suffix) + "]"
			}
		}
		used[key] = true
		newKey := reflect.ValueOf(key).Convert(value.Type().Key())
		updated := copyValue(item.value)
		sanitizeStrings(updated, clean)
		result.SetMapIndex(newKey, updated)
	}
	return result
}

func copyValue(value reflect.Value) reflect.Value {
	copy := reflect.New(value.Type()).Elem()
	copy.Set(value)
	return copy
}
