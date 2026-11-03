package sanitizer

import (
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/models"
)

var (
	windowsUserPath = regexp.MustCompile(`(?i)([a-z]:\\(?:users|documents and settings)\\)[^\\/:]+`)
	posixUserPath   = regexp.MustCompile(`(?i)(/(?:home|users)/)[^/\\\s]+`)
	rootPath        = regexp.MustCompile(`(?i)(/root)(/|$)`)
	macAddress      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	ipCandidate     = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{0,4}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:%[a-z0-9_.-]+)?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
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
		// Match identifiers as components so short host or account names do not
		// damage unrelated technical words.
		value = item.pattern.ReplaceAllString(value, `${1}`+item.token+`${3}`)
	}
	value = macAddress.ReplaceAllString(value, "[MAC_REDACTED]")
	value = ipCandidate.ReplaceAllStringFunc(value, func(candidate string) string {
		address := candidate
		if zone := strings.LastIndexByte(address, '%'); zone >= 0 {
			address = address[:zone]
		}
		if net.ParseIP(address) != nil {
			return "[IP_REDACTED]"
		}
		return candidate
	})
	return value
}

func newIdentifier(value, token string) identifier {
	item := identifier{value: value, token: token}
	if token == "[SERIAL_REDACTED]" {
		item.pattern = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(value))
	} else {
		componentChars := `A-Za-z0-9_.`
		item.pattern = regexp.MustCompile(`(?i)(^|[^` + componentChars + `])(` + regexp.QuoteMeta(value) + `)([^` + componentChars + `]|$)`)
	}
	return item
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
		iter := value.MapRange()
		for iter.Next() {
			updated := copyValue(iter.Value())
			sanitizeStrings(updated, clean)
			value.SetMapIndex(iter.Key(), updated)
		}
	case reflect.String:
		if value.CanSet() {
			value.SetString(clean(value.String()))
		}
	}
}

func copyValue(value reflect.Value) reflect.Value {
	copy := reflect.New(value.Type()).Elem()
	copy.Set(value)
	return copy
}
