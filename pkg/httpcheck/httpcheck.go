package httpcheck

import (
	"fmt"
	"github.com/TwiN/go-color"
	"net"
	"net/http"
)

// isPortOpen80 checks if port 80 is open for a domain by making an HTTP GET request.
func IsPortOpen80(domain string) (bool, error) {
	_, err := http.Get("http://" + domain)
	if err == nil {
		// If port 80 is open, check the IP address.
		ipAddr, err := net.LookupIP(domain)

		if err != nil {
			fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
			return false, err
		}
		fmt.Printf(color.Colorize(color.Green, "[+] %s is up (%s)\n"), domain, ipAddr[0])
		return true, nil

	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Domain not Resolved"))
		return false, err
	}
}

// isPortOpen443 checks if port 443 is open for a domain by making an HTTPS GET request.
func IsPortOpen443(domain string) (bool, error) {
	_, err := http.Get("https://" + domain)
	if err == nil {
		// If port 443 is open, check the IP address.
		ipAddr, err := net.LookupIP(domain)

		if err != nil {
			fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
			return false, err
		}
		fmt.Printf(color.Colorize(color.Green, "[+] %s is up (%s)\n"), domain, ipAddr[0])
		return true, nil

	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Domain not Resolved"))

		return false, err
	}
}
