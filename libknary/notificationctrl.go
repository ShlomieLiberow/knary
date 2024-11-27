package libknary

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Functions that control whether a match will notify a webhook.
// Currently the allow and denylists.

// map for allowlist
type allowlist struct {
	allow string
}

var allowed = map[int]allowlist{}
var allowCount = 0

// map for denylist
type blacklist struct {
	mutex sync.Mutex
	deny  map[string]time.Time
}

var denied = blacklist{deny: make(map[string]time.Time)}
var denyCount = 0

// add or update a denied domain/IP
func (a *blacklist) updateD(term string) bool {
	if term == "" {
		return false // would happen if there's no X-Forwarded-For header
	}
	a.mutex.Lock()
	a.deny[term] = time.Now()
	a.mutex.Unlock()
	return true
}

// search for a denied domain/IP
func (a *blacklist) searchD(term string) bool {
	if os.Getenv("DEBUG") == "true" {
		msg := fmt.Sprintf("Checking '%s' against denylist", term)
		Printy(msg, 3)
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.deny[term]; ok {
		return true
	}
	return false
}

func standerdiseListItem(term string) string {
	d := strings.ToLower(term) // lowercase
	d = strings.TrimSpace(d)   // remove any surrounding whitespaces
	var sTerm string

	if IsIP(d) {
		sTerm, _ = splitPort(d) // yeet port off IP
	} else {
		domain := strings.Split(d, ":")             // split on port number (if exists)
		sTerm = strings.TrimSuffix(domain[0], ".")  // remove trailing FQDN dot if present
		sTerm = strings.TrimPrefix(sTerm, "Host: ") // remove Host if present
	}

	return sTerm
}

func LoadAllowlist() (bool, error) {
	// load allowlist file into struct on startup
	if _, err := os.Stat(os.Getenv("ALLOWLIST_FILE")); os.IsNotExist(err) {
		return false, err
	}

	alwlist, err := os.Open(os.Getenv("ALLOWLIST_FILE"))
	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}
	defer alwlist.Close()

	scanner := bufio.NewScanner(alwlist)

	for scanner.Scan() { // foreach allowed item
		if scanner.Text() != "" {
			allowed[allowCount] = allowlist{standerdiseListItem(scanner.Text())}
			allowCount++
		}
	}

	Printy("Monitoring "+strconv.Itoa(allowCount)+" items in allowlist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(allowCount)+" items in allowlist")
	return true, nil
}

func LoadBlacklist() (bool, error) {
	if os.Getenv("BLACKLIST_FILE") != "" {
		// deprecation warning
		Printy("The environment variable \"DENYLIST_FILE\" has superseded \"BLACKLIST_FILE\". Please update your configuration.", 2)
	}
	// load denylist file into struct on startup
	if _, err := os.Stat(os.Getenv("DENYLIST_FILE")); os.IsNotExist(err) {
		return false, err
	}

	blklist, err := os.Open(os.Getenv("DENYLIST_FILE"))
	if err != nil {
		Printy(err.Error()+" - ignoring", 3)
		return false, err
	}
	defer blklist.Close()

	scanner := bufio.NewScanner(blklist)

	for scanner.Scan() { // foreach denied item
		if scanner.Text() != "" {
			denied.updateD(standerdiseListItem(scanner.Text()))
			denyCount++
		}
	}

	Printy("Monitoring "+strconv.Itoa(denyCount)+" items in denylist", 1)
	logger("INFO", "Monitoring "+strconv.Itoa(denyCount)+" items in denylist")
	return true, nil
}

func inAllowlist(needles ...string) bool {
	if allowed[0].allow == "" {
		return true // if there is no allowlist set, we skip this check
	}

	for _, needle := range needles {
		needle := standerdiseListItem(needle)
		for i := range allowed { // foreach allowed item
			if os.Getenv("ALLOWLIST_STRICT") == "true" {
				// strict matching. don't match subdomains
				if needle == allowed[i].allow {
					if os.Getenv("DEBUG") == "true" {
						logger("INFO", "Found "+needle+" in allowlist (strict mode)")
						Printy(needle+" matches allowlist", 3)
					}
					return true
				}
			} else {
				// allow fuzzy matching
				if strings.HasSuffix(needle, allowed[i].allow) {
					if os.Getenv("DEBUG") == "true" {
						logger("INFO", "Found "+needle+" in allowlist")
						Printy(needle+" matches allowlist", 3)
					}
					return true
				}
			}
		}
	}
	return false
}

func inBlacklist(needles ...string) bool {
	for _, needle := range needles {
		if len(strings.TrimSpace(needle)) == 0 {
			continue
		}

		// Skip core domain check
		if needle == os.Getenv("CANARY_DOMAIN") {
			if os.Getenv("DEBUG") == "true" {
				Printy("Skipping core domain: "+needle, 3)
			}
			return true
		}

		// Check if needle is a HTTP request
		if strings.Contains(needle, "GET ") || strings.Contains(needle, "POST ") ||
			strings.Contains(needle, "PUT ") || strings.Contains(needle, "DELETE ") {
			parts := strings.Fields(needle)
			if len(parts) >= 2 {
				path := strings.TrimPrefix(parts[1], "/")

				// Check if path matches any denylist entry
				for deniedItem := range denied.deny {
					if strings.Contains(path, deniedItem) {
						if os.Getenv("DEBUG") == "true" {
							Printy("Found match: '"+path+"' contains denylist entry '"+deniedItem+"'", 3)
						}
						denied.updateD(needle)
						return true
					}
				}
			}
		}

		if denied.searchD(needle) {
			denied.updateD(needle)
			if os.Getenv("DEBUG") == "true" {
				Printy("Found '"+needle+"' in denylist", 3)
			}
			return true
		}

		rootDomain, err := publicsuffix.EffectiveTLDPlusOne(needle)
		if err != nil {
			if os.Getenv("DEBUG") == "true" {
				Printy("Error parsing domain '"+needle+"'", 2)
			}
			continue
		}

		if rootDomain != strings.ToLower(rootDomain) && rootDomain != strings.ToUpper(rootDomain) {
			if os.Getenv("DEBUG") == "true" {
				Printy("Found mixed case in domain '"+needle+"'", 3)
			}
			return true
		}
	}
	return false
}

func checkLastHit() bool { // this runs once a day
	for subdomain := range denied.deny {
		expiryDate := denied.deny[subdomain].AddDate(0, 0, 14)

		if time.Now().After(expiryDate) { // let 'em know it's old
			msg := "Denied item `" + subdomain + "` hasn't had a hit in >14 days. Consider removing it."
			go sendMsg(":wrench: " + msg + " Configure `DENYLIST_ALERTING` to suppress.")
			logger("INFO", msg)
			Printy(msg, 1)
		}
	}

	if os.Getenv("DEBUG") == "true" {
		logger("INFO", "Checked denylist...")
		Printy("Checked for old denylist items", 3)
	}

	return true
}
