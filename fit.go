package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	c "github.com/lnquy/fit/config"
	"github.com/lnquy/fit/utils"
	"github.com/mvdan/xurls"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"path"
)

const (
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
	fRefreshTime  *int
	fStartup      *bool
	fSessionId    *string

	client  *http.Client
	ticker  *time.Ticker
	logFile *os.File
	//mw      io.Writer
	exit chan bool
)

func init() {
	// Write log to file and stdout
	var err error
	logPath, _ := os.Getwd()
	logPath = path.Join(logPath, "fit.log")
	if _, err = os.Stat(logPath); !os.IsNotExist(err) {
		os.Remove(logPath)
	}
	logFile, err = os.OpenFile("fit.log", os.O_RDWR|os.O_CREATE, 0666) // |os.O_APPEND
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	//mw = io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(logFile)

	fFortinetAddr = flag.String("a", "", "Fortigate <IP/Hostname:Port> address")
	fIsHttps = flag.Bool("h", true, "Is Fortigate server use HTTPS protocol?")
	fUsername = flag.String("u", "", "Your username")
	fPassword = flag.String("p", "", "Your password")
	fMaxRetries = flag.Int("n", 10, "Maximum retry times before terminating")
	fRefreshTime = flag.Int("r", 18000, "Time to wait until check and refresh Fortigate session in second")
	fStartup = flag.Bool("s", false, "Allow F.IT automatically run when your computer started up?")
	fSessionId = flag.String("i", "", "Your current Fortinet session ID")

	client = &http.Client{
		Timeout: time.Duration(REQ_TIMEOUT) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	exit = make(chan bool)
}

func main() {
	configure()
	defer logFile.Close()

	if c.Fit.SessionID != "" { // Terminate old session to handle new one
		logout()
	}

	var ok bool
	if c.Fit.SessionID, ok = getSessionID(); ok {
		log.Printf("Detected session ID: %s", c.Fit.SessionID)
		log.Println("Authenticating...")
		if c.Fit.SessionID = authenticate(c.Fit.SessionID); c.Fit.SessionID != "" {
			log.Printf("Authenticated. Current session ID: %s", c.Fit.SessionID)
			c.WriteToFile()
			log.Printf("Welcome to the Internet. Your session will be refreshed automatically in %d seconds", c.Fit.RefreshTime)
			keepAlive()
			<-exit
			log.Println("Terminated. Exiting...")
		} else {
			log.Printf("Maximum retried (%v). Please check your username/password. Exiting...", c.Fit.MaxRetries)
		}
	} else {
		log.Printf("Maximum retried (%v). Failed to detect Fortigate's session ID. Exiting...", c.Fit.MaxRetries)
	}
	log.Println("Have a good day. Bye mate!")

	// TODO: Exit gratefully
}

func getSessionID() (sId string, ok bool) {
	for i := 0; i < c.Fit.MaxRetries; i++ {
		log.Println("Detecting your current Fortigate session ID...")
		resp, err := client.Get(HOST_TARGET)
		if err != nil {
			log.Printf("Error: %s. Retrying in %v seconds...\n", err.Error(), REQ_TIMEOUT)
			time.Sleep(time.Duration(REQ_TIMEOUT) * time.Second)
			return
		}

		defer resp.Body.Close()
		//log.Printf("Request success. %#v\n", resp)
		fUrl := resp.Request.URL.String()
		if strings.Contains(fUrl, c.Fit.Address) && strings.Contains(fUrl, F_AUTH) {
			sId = fUrl[strings.Index(fUrl, "?")+1:]
			return sId, true
		}

		log.Printf("Detect Fortigate session ID failed. Retrying in %v seconds...", REQ_TIMEOUT)
		time.Sleep(time.Duration(REQ_TIMEOUT) * time.Second)
	}
	return
}

func authenticate(id string) (aId string) {
	for i := 0; i < c.Fit.MaxRetries; i++ {
		if aId = authenticateRequest(id); aId != "" {
			return
		}
		log.Printf("Authenticate failed. Retrying in %v seconds...", REQ_TIMEOUT)
		time.Sleep(time.Second * time.Duration(REQ_TIMEOUT))
	}
	return
}

func authenticateRequest(id string) (res string) {
	var req *http.Request
	var err error
	authUrl := utils.GetFortinetURL(c.Fit.IsHTTPS, c.Fit.Address, F_AUTH, id)
	authData := utils.GetAuthPostReqData(id, c.Fit.Username, c.Fit.Password)
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
			//log.Println("response Body:", string(body))
			if strings.Index(string(body), "/keepalive?") != -1 {
				if urls := xurls.Strict.FindAllString(string(body), -1); urls != nil {
					//log.Printf("%v", urls)
					return extractSessionIDFromUrls(urls)
				}
			}
		}
	}
	return
}

func extractSessionIDFromUrls(urls []string) string {
	for _, u := range urls {
		if strings.Contains(u, c.Fit.Address) && strings.Contains(u, F_ALIVE) {
			return u[strings.Index(u, F_ALIVE)+10:]
		}
	}
	return ""
}

func keepAlive() {
	ticker = time.NewTicker(time.Second * time.Duration(c.Fit.RefreshTime))
	go func() {
		for t := range ticker.C {
			log.Printf("Keep alive at %s", t)
			var ok bool
			for i := 0; i < c.Fit.MaxRetries; i++ {
				if resp, err := client.Get(utils.GetFortinetURL(c.Fit.IsHTTPS, c.Fit.Address, F_ALIVE, c.Fit.SessionID)); err != nil || resp.StatusCode != 200 {
					log.Printf("Keep alive failed. Retrying in %v seconds...", REQ_TIMEOUT)
					time.Sleep(time.Second * time.Duration(REQ_TIMEOUT))
				} else {
					log.Printf("Keep alive successed (%s). Next check after %d seconds", c.Fit.SessionID, c.Fit.RefreshTime)
					ok = true
					break
				}
			}

			if !ok {
				// TODO: Trying to logout and re-authenticate
				log.Println("Cannot refresh your session. Please check and try again!")
				ticker.Stop()
				exit <- true
			}
		}
	}()
}

func logout() (err error) {
	_, err = client.Get(utils.GetFortinetURL(c.Fit.IsHTTPS, c.Fit.Address, F_LOGOUT, c.Fit.SessionID))
	return
}

func configure() {
	c.ReadFromFile()

	// Override configs by CLI args
	flag.Parse()
	if *fFortinetAddr != "" {
		c.Fit.Address = *fFortinetAddr
	}
	if !*fIsHttps {
		c.Fit.IsHTTPS = *fIsHttps
	}
	if *fUsername != "" {
		c.Fit.Username = *fUsername
	}
	if *fPassword != "" {
		c.Fit.Password = *fPassword
	}
	if *fMaxRetries != 10 {
		c.Fit.MaxRetries = *fMaxRetries
	}
	if *fRefreshTime != 18000 {
		c.Fit.RefreshTime = *fRefreshTime
	}
	if *fStartup {
		c.Fit.AutoStartup = *fStartup
	}
	if *fSessionId != "" {
		c.Fit.SessionID = *fSessionId
	}

	if c.Fit.Address == "" || c.Fit.Username == "" || c.Fit.Password == "" {
		log.Print("Fortinet server address, username and password must be specified via configuration file or CLI arguments. Exiting...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	utils.PrintBanner()

	// Protect plaintext password
	if !strings.HasPrefix(c.Fit.Password, "${") || !strings.HasSuffix(c.Fit.Password, "}$") {
		utils.ProtectPassword(c.Fit)
		*fPassword = "" // Prevent plaintext password still store in memory
	}

	if c.Fit.AutoStartup {
		if err := utils.SetStartupShortcut(); err != nil {
			log.Printf("[Config] Cannot set startup shortcut for F.IT program on your computer. Error: %s", err)
		} else {
			log.Print("[Config] F.IT will automatically start with your computer!")
		}
	} else {
		lnkPath := path.Join(utils.UserHomeDir(), "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fit.lnk")
		if _, err := os.Stat(lnkPath); !os.IsNotExist(err) {
			if err := os.Remove(lnkPath); err != nil {
				log.Printf("Cannot delete F.IT startup shortcut: %s", lnkPath)
			}
		}
	}
}
