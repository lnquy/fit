package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	cfg "github.com/lnquy/fit/conf"
	"github.com/lnquy/fit/modules/boot"
	glb "github.com/lnquy/fit/modules/global"
	"github.com/lnquy/fit/utils"
	"github.com/mvdan/xurls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

var (
	// Flags
	fDebug        *bool
	fFortinetAddr *string
	fIsHttps      *bool
	fUsername     *string
	fPassword     *string
	fMaxRetries   *int
	fRefreshTime  *int
	fStartup      *bool
	fSessionId    *string

	client  *http.Client
	ticker  *time.Ticker // Ticker for refreshing session id
	logFile *os.File
	mw      io.Writer // Multi writer
	exit    chan bool
)

func init() {
	fDebug = flag.Bool("d", false, "Debug mode") // Debug mode will write log to both stdout and file
	fFortinetAddr = flag.String("ip", "", "Fortigate <IP/Hostname:Port> address")
	fIsHttps = flag.Bool("https", true, "Is Fortigate server use HTTPS protocol?")
	fUsername = flag.String("username", "", "Your username")
	fPassword = flag.String("password", "", "Your password")
	fMaxRetries = flag.Int("retries", glb.DEFAULT_MAX_RETRIES, "Maximum retry times before terminating")
	fRefreshTime = flag.Int("refresh", glb.DEFAULT_REFRESH_TIME, "Time to wait until check and refresh Fortigate session in second")
	fStartup = flag.Bool("auto-start", false, "Allow F.IT automatically run when your computer started up?")
	fSessionId = flag.String("session-id", "", "Your current Fortinet session ID")

	client = &http.Client{
		Timeout: time.Duration(glb.DEFAULT_REQ_TIMEOUT) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	exit = make(chan bool)
}

func configure() {
	cfg.ReadFromFile()

	// Override configs by CLI args
	flag.Parse()
	if *fFortinetAddr != "" {
		cfg.Fit.Address = *fFortinetAddr
	}
	if !*fIsHttps {
		cfg.Fit.IsHTTPS = *fIsHttps
	}
	if *fUsername != "" {
		cfg.Fit.Username = *fUsername
	}
	if *fPassword != "" {
		cfg.Fit.Password = *fPassword
	}
	*fPassword = ""
	if *fMaxRetries != glb.DEFAULT_MAX_RETRIES {
		cfg.Fit.MaxRetries = *fMaxRetries
	}
	if *fRefreshTime != glb.DEFAULT_REFRESH_TIME {
		cfg.Fit.RefreshTime = *fRefreshTime
	}
	if *fStartup {
		cfg.Fit.AutoStartup = *fStartup
	}
	if *fSessionId != "" {
		cfg.Fit.SessionID = *fSessionId
	}

	// Configure log output
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
	if *fDebug {
		mw = io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	} else {
		log.SetOutput(logFile)
	}

	// Validate required fields
	if cfg.Fit.Address == "" || cfg.Fit.Username == "" || cfg.Fit.Password == "" {
		log.Print("Fortinet server address, username and password must be specified via configuration file or CLI arguments. Exiting...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	utils.PrintBanner()

	// Protect plaintext password
	if !strings.HasPrefix(cfg.Fit.Password, "${") || !strings.HasSuffix(cfg.Fit.Password, "}$") {
		if pp := utils.GetProtectedPassword(cfg.Fit.Password); pp != "" {
			cfg.Fit.Password = pp
			if err := cfg.WriteToFile(); err != nil {
				log.Println("[Config] Cannot write encrypted password to file", err)
			} else {
				log.Println("[Config] Your password has been encrypted automatically")
			}
		}
	}

	// Auto start when computer booting up
	if cfg.Fit.AutoStartup {
		boot.EnableAutoStartup()
	} else {
		boot.DisableAutoStartup()
	}
}

func getSessionID() (sId string, ok bool) {
	for i := 0; i < cfg.Fit.MaxRetries; i++ {
		log.Println("Detecting your current Fortigate session ID...")
		resp, err := client.Get(glb.TEST_TARGET)
		if err != nil {
			log.Printf("Error: %s. Retrying in %v seconds...\n", err.Error(), glb.DEFAULT_REQ_TIMEOUT)
			time.Sleep(time.Duration(glb.DEFAULT_REQ_TIMEOUT) * time.Second)
			continue
		}

		//log.Printf("Request success. %#v\n", resp)
		fUrl := resp.Request.URL.String()
		resp.Body.Close()
		if strings.Contains(fUrl, cfg.Fit.Address) && strings.Contains(fUrl, glb.F_AUTH) {
			sId = fUrl[strings.Index(fUrl, "?")+1:]
			return sId, true
		}

		log.Printf("Detect Fortigate session ID failed. Retrying in %v seconds...", glb.DEFAULT_REQ_TIMEOUT)
		time.Sleep(time.Duration(glb.DEFAULT_REQ_TIMEOUT) * time.Second)
	}
	return
}

func authenticate(id string) (aId string) {
	for i := 0; i < cfg.Fit.MaxRetries; i++ {
		if aId = authenticateRequest(id); aId != "" {
			return
		}
		log.Printf("Authenticate failed. Retrying in %v seconds...", glb.DEFAULT_REQ_TIMEOUT)
		time.Sleep(time.Second * time.Duration(glb.DEFAULT_REQ_TIMEOUT))
	}
	return
}

func authenticateRequest(id string) (res string) {
	var req *http.Request
	var err error
	authUrl := utils.GetFortinetURL(cfg.Fit.IsHTTPS, cfg.Fit.Address, glb.F_AUTH, id)
	authData := utils.GetAuthPostReqData(id, cfg.Fit.Username, cfg.Fit.Password)
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
		if strings.Contains(u, cfg.Fit.Address) && strings.Contains(u, glb.F_ALIVE) {
			return u[strings.Index(u, glb.F_ALIVE)+10:]
		}
	}
	return ""
}

func keepAlive() {
	ticker = time.NewTicker(time.Second * time.Duration(cfg.Fit.RefreshTime))
	go func() {
		for t := range ticker.C {
			log.Printf("Keep alive at %s", t)
			var ok bool
			for i := 0; i < cfg.Fit.MaxRetries; i++ {
				if resp, err := client.Get(utils.GetFortinetURL(cfg.Fit.IsHTTPS, cfg.Fit.Address, glb.F_ALIVE, cfg.Fit.SessionID)); err != nil || resp.StatusCode != 200 {
					log.Printf("Keep alive failed. Retrying in %v seconds...", glb.DEFAULT_REQ_TIMEOUT)
					time.Sleep(time.Second * time.Duration(glb.DEFAULT_REQ_TIMEOUT))
				} else {
					log.Printf("Keep alive successed (%s). Next check after %d seconds", cfg.Fit.SessionID, cfg.Fit.RefreshTime)
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

func logout() error {
	resp, err := client.Get(utils.GetFortinetURL(cfg.Fit.IsHTTPS, cfg.Fit.Address, glb.F_LOGOUT, cfg.Fit.SessionID))
	defer resp.Body.Close()
	return err
}

func main() {
	configure()
	defer logFile.Close()

	if cfg.Fit.SessionID != "" { // Terminate old session to handle new one
		logout()
	}

	var ok bool
	if cfg.Fit.SessionID, ok = getSessionID(); ok {
		log.Printf("Detected session ID: %s", cfg.Fit.SessionID)
		log.Println("Authenticating...")
		time.Sleep(time.Duration(1) * time.Second) // Wait HTTP client to release transaction
		if cfg.Fit.SessionID = authenticate(cfg.Fit.SessionID); cfg.Fit.SessionID != "" {
			log.Printf("Authenticated. Current session ID: %s", cfg.Fit.SessionID)
			cfg.WriteToFile()
			log.Printf("Welcome to the Internet. Your session will be refreshed automatically in %d seconds", cfg.Fit.RefreshTime)
			keepAlive()
			<-exit
			log.Println("Terminated. Exiting...")
		} else {
			log.Printf("Maximum retried (%v). Please check your username/password. Exiting...", cfg.Fit.MaxRetries)
		}
	} else {
		log.Printf("Maximum retried (%v). Failed to detect Fortigate's session ID. Exiting...", cfg.Fit.MaxRetries)
	}
	log.Println("Have a good day. Bye mate!")

	// TODO: Exit gratefully
}
