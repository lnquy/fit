package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"
	"fmt"
	"io/ioutil"
	"bytes"
	"github.com/lnquy/fit/utils"
)

const (
	REQ_TIMEOUT int    = 10
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

	client    *http.Client
	sessionId string
)

func init() {
	fFortinetAddr = flag.String("a", "192.168.10.1:1003", "FortiGate <IP/Hostname:Port> address")
	fIsHttps = flag.Bool("s", true, "Is FortiGate server use HTTPS protocol?")
	fFortinetAddr = flag.String("u", "", "Your username")
	fFortinetAddr = flag.String("p", "", "Your password")

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
	if sId, ok := getSessionID(); ok {
		log.Printf("Your session ID: %s\nAuthenticating...\n", sId)
		if fId := authenticate(sId); fId != "" {
			log.Printf("Authenticated! fid: %s", fId)

			// TODO: Keepalive
		} else {
			log.Println("Authentication failed!")
		}
	} else {
		log.Println("Unable to detect FortiGate's session ID. Exiting...")
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
		return
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("response Status:", resp.Status)
		fmt.Println("response Headers:", resp.Header)
		fmt.Println("response Body:", string(body))

		return "OK"
	}
	return
}

func getSessionID() (sId string, ok bool) {
	for i := 0; i < *fMaxRetries; i++ {
		resp, err := client.Get(HOST_TARGET)
		if err != nil {
			log.Printf("Failed to get %s. Error: %s\n", HOST_TARGET, err.Error())
			return
		}

		defer resp.Body.Close() // TODO: Any other solutions here?
		log.Printf("Request successed. %#v\n", resp)
		fUrl := resp.Request.URL.String()
		log.Printf("Final URL: %s\n", fUrl)
		if strings.Contains(fUrl, *fFortinetAddr) && strings.Contains(fUrl, F_AUTH) {
			sId = fUrl[strings.Index(fUrl, "?")+1:]
			return sId, true
		}

		log.Printf("Unable to detect FortiGate's session ID. Retrying in %v seconds...", REQ_TIMEOUT)
		time.Sleep(time.Duration(REQ_TIMEOUT) * time.Second)
	}
	return
}
