package cdncheck

import (
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/projectdiscovery/cdncheck"
	"net"
)

// isCDN checks if a domain is using a CDN by  IP Address.

func IsCDN(domain string) (bool, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	ipAddr, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
		return false, ""
	}

	client := cdncheck.New()
	ip := ipAddr[0]

	// checks if an IP is contained in the cdn denylist
	matched, val, err := client.CheckCDN(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf(color.Colorize(color.Green, "[+] %s On the CDN (%s)\n"), domain, val)
		return matched, val

	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is Not in CDN\n"), domain)
		return matched, val

	}

	return false, ""
}

// isCloud checks if a domain is using a Cloud by  IP Address.
func IsCloud(domain string) (bool, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	ipAddr, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
		return false, ""
	}

	client := cdncheck.New()
	ip := ipAddr[0]

	// checks if an IP is contained in the cloud denylist
	matched, val, err := client.CheckCloud(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf(color.Colorize(color.Green, "[+] %s On the Cloud (%s)\n"), domain, val)
		return matched, val

	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is Not in Cloud\n"), domain)
		return matched, val

	}

	return false, ""
}

// isWaf checks if a domain is using a Cloud by IP Address.

func IsWaf(domain string) (bool, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	ipAddr, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
		return false, ""
	}

	client := cdncheck.New()
	ip := ipAddr[0]

	// checks if an IP is contained in the waf denylist
	matched, val, err := client.CheckWAF(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf(color.Colorize(color.Green, "[+] %s Has Waf (%s)\n"), domain, val)
		return matched, val

	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] %s has not WAF\n"), domain)
		return matched, val

	}
	return false, ""
}
