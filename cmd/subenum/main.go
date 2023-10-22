package main

import (
	"encoding/csv"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/destan0098/subenum/pkg/cdncheck"
	"github.com/destan0098/subenum/pkg/httpcheck"
	"github.com/destan0098/subenum/pkg/subfind"
	"github.com/urfave/cli/v2"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type DomainResult struct {
	Domain    string
	Port80    bool
	Port443   bool
	IsCDN     bool
	CDNname   string
	isCloud   bool
	CloudName string
	isWAF     bool
	WAFname   string
}

var outputs, inputs, domains string = "", "", ""

var pipel, cdn int
var results []DomainResult

func main() {

	// Print usage example and information about the tool.
	//fmt.Printf(color.Colorize(color.Green, `Example Of Use : Subcheck.go -i 'C:\Users\**\Desktop\go2\checksubdomains\input.txt' -o 'C:\Users\***\Desktop\go2\checksubdomains\result4.csv'`) + "\n")
	fmt.Println(`


  /$$$$$$            /$$             /$$$$$$$$                                  
 /$$__  $$          | $$            | $$_____/                                  
| $$  \__/ /$$   /$$| $$$$$$$       | $$       /$$$$$$$  /$$   /$$ /$$$$$$/$$$$ 
|  $$$$$$ | $$  | $$| $$__  $$      | $$$$$   | $$__  $$| $$  | $$| $$_  $$_  $$
 \____  $$| $$  | $$| $$  \ $$      | $$__/   | $$  \ $$| $$  | $$| $$ \ $$ \ $$
 /$$  \ $$| $$  | $$| $$  | $$      | $$      | $$  | $$| $$  | $$| $$ | $$ | $$
|  $$$$$$/|  $$$$$$/| $$$$$$$/      | $$$$$$$$| $$  | $$|  $$$$$$/| $$ | $$ | $$
 \______/  \______/ |_______/       |________/|__/  |__/ \______/ |__/ |__/ |__/
                                                                                
                                                                                
                                                                                

`)
	fmt.Println(color.Colorize(color.Red, "[*] This tool is for training."))
	fmt.Println(color.Colorize(color.Red, "[*]Enter subenum -h to show help"))
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "domain",
				Value:       "",
				Aliases:     []string{"d"},
				Usage:       "Enter just one domain",
				Destination: &domains,
			},
			&cli.StringFlag{
				Name:        "list",
				Value:       "",
				Aliases:     []string{"l"},
				Usage:       "Enter a list from text file",
				Destination: &inputs,
			},
			&cli.BoolFlag{
				Name:  "pipe",
				Usage: "Enter just from pipe line",
				Count: &pipel,
			},
			&cli.BoolFlag{
				Name:    "cdn",
				Aliases: []string{"c"},
				Usage:   "check cdn and waf and cloud",
				Count:   &cdn,
			},

			&cli.StringFlag{
				Name:        "output",
				Value:       "output.csv",
				Aliases:     []string{"o"},
				Usage:       "Enter output csv file name  ",
				Destination: &outputs,
			},
		},
		Action: func(cCtx *cli.Context) error {
			if domains != "" {
				results = withname(domains)
				writeResults(results, outputs)
			} else if inputs != "" {
				results = withlist(inputs)
				writeResults(results, outputs)
			} else if pipel > 0 {
				results = withpip()
				writeResults(results, outputs)
			}
			//	withlist("list", wg)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}

// readDomains reads domain names from a text file and returns them as a string slice.

func writeResults(results []DomainResult, outputfile string) {

	file, err := os.Create(outputfile)
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	// Write the results to a CSV file.
	writer := csv.NewWriter(file)
	defer writer.Flush()
	err = writer.Write([]string{"Domain", "Port 80", "Port 443", "Is CDN", "CDN Name", "Is Cloud", "Cloud name", "has Waf", "WAF name"})
	if err != nil {
		return
	}
	for _, result := range results {
		err = writer.Write([]string{result.Domain, fmt.Sprintf("%v", result.Port80), fmt.Sprintf("%v", result.Port443), fmt.Sprintf("%v", result.IsCDN), fmt.Sprintf("%v", result.CDNname), fmt.Sprintf("%v", result.isCloud), fmt.Sprintf("%v", result.CloudName), fmt.Sprintf("%v", result.isWAF), fmt.Sprintf("%v", result.WAFname)})
		if err != nil {
			return
		}
	}
}
func withname(domain string) []DomainResult {
	var result DomainResult

	if strings.HasPrefix(domain, "https://") {
		if strings.HasPrefix(domain, "http://") {
			fmt.Println(color.Colorize(color.Red, "Input Domain Without http or https"))
			time.Sleep(2 * time.Second)
			os.Exit(1)

		}

	}
	subdomains := subfind.Subfind(domain)
	for {
		line, err := subdomains.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println(err)
			return nil
		}

		domain = string(line)
		domain = removeNewline(domain)

		// Check if port 80 is open for the domain.
		port80, err80 := httpcheck.IsPortOpen80(domain)

		// Check if port 443 is open for the domain.
		port443, err443 := httpcheck.IsPortOpen443(domain)
		if cdn > 0 {
			// Check if the domain is on a CDN.
			isCDNs, CDNname := cdncheck.IsCDN(domain)
			isClouds, CloudName := cdncheck.IsCloud(domain)
			isWAFs, WAFname := cdncheck.IsWaf(domain)

			result = DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     isCDNs,
				CDNname:   CDNname,
				isCloud:   isClouds,
				CloudName: CloudName,
				isWAF:     isWAFs,
				WAFname:   WAFname,
			}
		} else {
			result = DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     false,
				CDNname:   "",
				isCloud:   false,
				CloudName: "",
				isWAF:     false,
				WAFname:   "",
			}
		}
		// If port 80 or 443 is open, print a message and store the result.
		if result.Port80 || port443 {
			fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
			results = append(results, result)
		}
	}
	return results
}

func removeNewline(url string) string {
	return strings.ReplaceAll(url, "\n", "")

}
func withlist(inputfile string) []DomainResult {

	var result DomainResult
	subdomains := subfind.Subfindfile(inputfile)
	for {
		line, err := subdomains.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println(err)
			return nil
		}

		domain := string(line)
		domain = removeNewline(domain)

		// Check if port 80 is open for the domain.
		port80, err80 := httpcheck.IsPortOpen80(domain)

		// Check if port 443 is open for the domain.
		port443, err443 := httpcheck.IsPortOpen443(domain)
		if cdn > 0 {
			// Check if the domain is on a CDN.
			isCDNs, CDNname := cdncheck.IsCDN(domain)
			isClouds, CloudName := cdncheck.IsCloud(domain)
			isWAFs, WAFname := cdncheck.IsWaf(domain)

			result = DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     isCDNs,
				CDNname:   CDNname,
				isCloud:   isClouds,
				CloudName: CloudName,
				isWAF:     isWAFs,
				WAFname:   WAFname,
			}
		} else {
			result = DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     false,
				CDNname:   "",
				isCloud:   false,
				CloudName: "",
				isWAF:     false,
				WAFname:   "",
			}
		}
		// If port 80 or 443 is open, print a message and store the result.
		if result.Port80 || port443 {
			fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
			results = append(results, result)
		}

	}

	return results
}

func withpip() []DomainResult {
	var result DomainResult
	subdomains := subfind.Subfindpipe(os.Stdin)
	for {
		line, err := subdomains.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println(err)
			return nil
		}

		domain := string(line)
		domain = removeNewline(domain)
		//domainBytes := scanner.Bytes()
		//domain := scanner.Text()

		domain = removeNewline(domain)
		//	fmt.Println(domain)
		//	fmt.Println(len(domain))

		// Check if port 80 is open for the domain.
		port80, err80 := httpcheck.IsPortOpen80(domain)

		// Check if port 443 is open for the domain.
		port443, err443 := httpcheck.IsPortOpen443(domain)
		if cdn > 0 {
			// Check if the domain is on a CDN.
			isCDNs, CDNname := cdncheck.IsCDN(domain)
			isClouds, CloudName := cdncheck.IsCloud(domain)
			isWAFs, WAFname := cdncheck.IsWaf(domain)

			result = DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     isCDNs,
				CDNname:   CDNname,
				isCloud:   isClouds,
				CloudName: CloudName,
				isWAF:     isWAFs,
				WAFname:   WAFname,
			}
		} else {
			result = DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     false,
				CDNname:   "",
				isCloud:   false,
				CloudName: "",
				isWAF:     false,
				WAFname:   "",
			}
		}

		// If port 80 or 443 is open, print a message and store the result.
		if result.Port80 || port443 {
			fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
			results = append(results, result)
		}

	}

	return results
}
