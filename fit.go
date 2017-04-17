package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/lnquy/fit/utils"
	"github.com/mvdan/xurls"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	REFRESH_TIME int = 18000 // Seconds
	REQ_TIMEOUT int    = 15
	HOST_TARGET string = "https://google.com"
	F_AUTH      string = "fgtauth"
	F_ALIVE     string = "keepalive"
	F_LOGOUT    string = "logout"
)

var (
	// Flags
	fFortinetAddr *string
	fIsHttps      *bool
	fUsername     *string
	fPassword     *string
	fMaxRetries   *int

	client *http.Client
	ticker *time.Ticker
	sId    string // Current session ID
)

func init() {
	fFortinetAddr = flag.String("a", "192.168.10.1:1003", "Fortigate <IP/Hostname:Port> address")
	fIsHttps = flag.Bool("s", true, "Is Fortigate server use HTTPS protocol?")
	fUsername = flag.String("u", "", "Your username")
	fPassword = flag.String("p", "", "Your password")
	fMaxRetries = flag.Int("r", 10, "Maximum retry times before terminating")

	client = &http.Client{
		Timeout: time.Duration(REQ_TIMEOUT) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func main() {
	flag.Parse()

	var ok bool
	if sId, ok = getSessionID(); ok {
		log.Printf("Your current session ID is: %s.\nAuthenticating...\n", sId)
		if sId = authenticate(sId); sId != "" {
			log.Printf("Authenticated with new session ID: %s", sId)

			// TODO: Keepalive
		} else {
			log.Println("Authentication failed. Please check your username/password. Exiting...")
		}
	} else {
		log.Printf("Maximum retried (%v). Failed to detect Fortigate's session ID. Exiting...\n", *fMaxRetries)
	}
}

func authenticate(sId string) (fId string) {
	var req *http.Request
	var err error
	authUrl := utils.GetFortinetURL(*fIsHttps, *fFortinetAddr, F_AUTH, sId)
	authData := utils.GetAuthPostReqData(sId, *fUsername, *fPassword)
	if req, err = http.NewRequest("POST", authUrl, bytes.NewBuffer([]byte(authData))); err != nil {
		return
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cache-control", "no-cache")
	if resp, err := client.Do(req); err != nil {
		log.Printf("Error: %s", err.Error())
		return
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}

		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			return
		} else {
			fmt.Println("response Body:", string(body))
			// TODO: Get timeout
			if strings.Index(string(body), "/keepalive?") != -1 {
				if urls := xurls.Strict.FindAllString(string(body), -1); urls != nil {
					log.Printf("%v", urls)
					return extractSessionIDFromUrls(urls)
				}
			}
		}
	}
	return
}

func getSessionID() (sId string, ok bool) {
	for i := 0; i < *fMaxRetries; i++ {
		log.Println("Detecting your current Fortigate's session ID...")
		resp, err := client.Get(HOST_TARGET)
		if err != nil {
			log.Printf("Error: %s. Will retry in %v seconds...\n", err.Error(), REQ_TIMEOUT)
			time.Sleep(time.Duration(REQ_TIMEOUT) * time.Second)
			return
		}

		defer resp.Body.Close() // TODO: Any other solutions here?
		log.Printf("Request successed. %#v\n", resp)
		fUrl := resp.Request.URL.String()
		if strings.Contains(fUrl, *fFortinetAddr) && strings.Contains(fUrl, F_AUTH) {
			sId = fUrl[strings.Index(fUrl, "?")+1:]
			return sId, true
		}

		log.Printf("Unable to detect your Fortigate's session ID. Will retry in %v seconds...", REQ_TIMEOUT)
		time.Sleep(time.Duration(REQ_TIMEOUT) * time.Second)
	}
	return
}

func extractSessionIDFromUrls(urls []string) string {
	for _, u := range urls {
		if strings.Contains(u, *fFortinetAddr) && strings.Contains(u, F_AUTH) {
			return u[strings.Index(u, F_AUTH)+2:]
		}
	}
	return ""
}

func keepalive() {
	ticker = time.NewTicker(time.Second * time.Duration(REFRESH_TIME)) // TODO: Ticker by timeout
	go func() {
		for t := range ticker.C {
			fmt.Println("Tick at", t)
			// TODO: keepalive worker
		}
	}()
}
