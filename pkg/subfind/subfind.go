package subfind

import (
	"bytes"
	"context"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"log"
	"os"
)

func Subfindfile(domains string) *bytes.Buffer {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration

	}
	log.SetFlags(0)
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}
	file, err := os.Open(domains)
	if err != nil {
		log.Fatalf("failed to open domains file: %v", err)
	}
	defer file.Close()
	output := &bytes.Buffer{}
	if err = subfinder.EnumerateMultipleDomainsWithCtx(context.Background(), file, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate subdomains from file: %v", err)
	}
	//log.Println(output.String())
	return output
}
func removeBOM(data []byte) []byte {
	// Check for common BOMs (UTF-8, UTF-16LE, UTF-16BE) and remove them.
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:] // Remove UTF-8 BOM
	}
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return data[2:] // Remove UTF-16LE BOM
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return data[2:] // Remove UTF-16BE BOM
	}
	return data
}
func Subfindpipe(reader io.Reader) *bytes.Buffer {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration

	}
	log.SetFlags(0)
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}
	buffer := new(bytes.Buffer)
	_, err = io.Copy(buffer, reader)
	if err != nil {
		panic(err)
	}

	// Get the modified data (without BOM)
	modifiedData := removeBOM(buffer.Bytes())

	// Create a new io.Reader from the modified data
	reader = bytes.NewReader(modifiedData)
	output := &bytes.Buffer{}

	if err = subfinder.EnumerateMultipleDomainsWithCtx(context.Background(), reader, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate subdomains from file: %v", err)
	}
	//log.Println(output.String())
	return output
}
func Subfind(domain string) *bytes.Buffer {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration

	}
	log.SetFlags(0)

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}
	// To run subdomain enumeration on a single domain
	if err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate single domain: %v", err)
	}

	return output
}
