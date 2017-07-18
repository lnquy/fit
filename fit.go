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
	"os/signal"
	"path"
	"strings"
	"syscall"
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
	fTermTime     *string
	fSessionId    *string

	client  *http.Client
	logFile *os.File
	mw      io.Writer      // Multi writer
	exit    chan os.Signal // Graceful exit channel
)

func init() {
	fDebug = flag.Bool("d", false, "Debug mode") // Debug mode will write log to both stdout and file
	fFortinetAddr = flag.String("ip", "", "Fortigate <IP/Hostname:Port> address")
	fIsHttps = flag.Bool("https", true, "Is Fortigate server use HTTPS protocol?")
	fUsername = flag.String("username", "", "Your username")
	fPassword = flag.String("password", "", "Your password")
	fMaxRetries = flag.Int("retries", glb.DEFAULT_MAX_RETRIES, "Maximum retry times before terminating old session")
	fRefreshTime = flag.Int("refresh", glb.DEFAULT_REFRESH_TIME, "Time to wait until check and refresh Fortigate session in second")
	fStartup = flag.Bool("start", false, "Allow F.IT automatically run when your computer started up?")
	fTermTime = flag.String("termination", glb.DEFAULT_TERM_TIME, "Time of the day (h:m:s) when F.IT terminates old session and retrieves new one")
	fSessionId = flag.String("session", "", "Your current Fortigate session ID")

	client = &http.Client{
		Timeout: time.Duration(glb.DEFAULT_REQ_TIMEOUT) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	exit = make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGTERM, syscall.SIGINT)
}

func configure() {
	cfg.ReadFromFile()

	// Override file configs by CLI args
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
	if *fTermTime != glb.DEFAULT_TERM_TIME {
		if _, _, _, err := utils.ParseTerminationTime(*fTermTime); err != nil {
			cfg.Fit.TerminationTime = glb.DEFAULT_TERM_TIME
		} else {
			cfg.Fit.TerminationTime = *fTermTime
		}
	}
	if *fSessionId != "" {
		cfg.Fit.SessionID = *fSessionId
	}

	// Configure log output
	logPath, _ := os.Getwd()
	logPath = path.Join(logPath, "fit.log")
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		os.Remove(logPath) // Remove old log files
	}
	var err error
	logFile, err = os.OpenFile("fit.log", os.O_RDWR|os.O_CREATE, 0666) // |os.O_APPEND
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	if *fDebug {
		mw = io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
		log.Println("Debugging on. Write log to both log/fit.log file and stdout")
	} else {
		log.SetOutput(logFile)
	}

	// Validate required fields
	if cfg.Fit.Address == "" || cfg.Fit.Username == "" || cfg.Fit.Password == "" {
		log.Print("Fortigate server address, username and password must be specified via configuration file or CLI arguments. Exiting...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	utils.PrintBanner()

	// Protect plaintext password
	if !strings.HasPrefix(cfg.Fit.Password, "${") || !strings.HasSuffix(cfg.Fit.Password, "}$") {
		if pp := utils.GetProtectedPassword(cfg.Fit.Password); pp != "" {
			cfg.Fit.Password = pp
			if err := cfg.WriteToFile(); err != nil {
				log.Printf("Failed to write encrypted password to file: %s", err)
			} else {
				log.Println("Your password has been encrypted automatically")
			}
		}
	}

	// Auto start when computer booting up
	if cfg.Fit.AutoStartup {
		boot.EnableAutoStartup()
	} else {
		boot.DisableAutoStartup()
	}

	cfg.WriteToFile()
}

func getSessionID() (sId string, ok bool) {
	for i := 0; i < cfg.Fit.MaxRetries; i++ {
		log.Println("Detecting your current Fortigate session ID...")
		resp, err := client.Get(glb.TEST_TARGET)
		if err != nil {
			log.Printf("Error: %s. Retrying in %v seconds...\n", err.Error(), glb.WAIT_TIME)
			time.Sleep(time.Duration(glb.WAIT_TIME) * time.Second)
			continue
		}

		//log.Printf("Request success. %#v\n", resp)
		fUrl := resp.Request.URL.String()
		resp.Body.Close()
		if strings.Contains(fUrl, cfg.Fit.Address) && strings.Contains(fUrl, glb.F_AUTH) {
			sId = fUrl[strings.Index(fUrl, "?")+1:]
			return sId, true
		}

		log.Printf("Failed to detect Fortigate session ID. Retrying in %v seconds...", glb.WAIT_TIME)
		time.Sleep(time.Duration(glb.WAIT_TIME) * time.Second)
	}
	return
}

func authenticate(id string) (aId string) {
	for i := 0; i < cfg.Fit.MaxRetries; i++ {
		if aId = authRequest(id); aId != "" {
			return
		}
		log.Printf("Authenticate failed. Retrying in %v seconds...", glb.WAIT_TIME)
		time.Sleep(time.Second * time.Duration(glb.WAIT_TIME))
	}
	return
}

func authRequest(id string) (res string) {
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
					return utils.ExtractSessionIDFromUrls(urls)
				}
			}
		}
	}
	return
}

func keepAlive(retChan chan bool) {
	refTicker := time.NewTicker(time.Second * time.Duration(cfg.Fit.RefreshTime))
	termTicker := utils.GetTerminationTicker()
	for {
		select {
		case t := <-refTicker.C:
			log.Printf("Keep alive tick at %s", t)
			var ok bool
			for i := 0; i < cfg.Fit.MaxRetries; i++ {
				if resp, err := client.Get(utils.GetFortinetURL(cfg.Fit.IsHTTPS, cfg.Fit.Address, glb.F_ALIVE, cfg.Fit.SessionID)); err != nil || resp.StatusCode != 200 {
					log.Printf("Keep alive failed. Retrying in %v seconds...", glb.WAIT_TIME)
					time.Sleep(time.Second * time.Duration(glb.WAIT_TIME))
				} else {
					log.Printf("Keep alive successed (%s). Next check after %d seconds", cfg.Fit.SessionID, cfg.Fit.RefreshTime)
					ok = true
					break
				}
			}

			if !ok {
				log.Printf("Failed to refresh session %s", cfg.Fit.SessionID)
				refTicker.Stop()
				termTicker.Stop()
				retChan <- true // Try to terminate old session and handle new one
				return
			}
		case t := <-termTicker.C:
			log.Printf("Terminate session tick at: %v", t)
			refTicker.Stop()
			termTicker.Stop()
			retChan <- true
			return
		}
	}
}

func logout() error {
	resp, err := client.Get(utils.GetFortinetURL(cfg.Fit.IsHTTPS, cfg.Fit.Address, glb.F_LOGOUT, cfg.Fit.SessionID))
	if err == nil {
		log.Printf("Terminated your Fortigate session (%v)", cfg.Fit.SessionID)
		cfg.Fit.SessionID = ""
	}
	defer resp.Body.Close()
	return err
}

func fit() bool {
	var ok bool
	if cfg.Fit.SessionID, ok = getSessionID(); ok {
		log.Printf("Fortigate session ID detected: %s", cfg.Fit.SessionID)
		log.Println("Authenticating...")
		time.Sleep(time.Second * time.Duration(glb.WAIT_TIME)) // Wait HTTP client to release transaction
		if cfg.Fit.SessionID = authenticate(cfg.Fit.SessionID); cfg.Fit.SessionID != "" {
			log.Printf("Authenticated. Current session ID: %s", cfg.Fit.SessionID)
			log.Printf("Welcome to the Internet. Your session will be refreshed automatically in %d seconds", cfg.Fit.RefreshTime)
			cfg.WriteToFile()

			kaChan := make(chan bool, 1)
			go keepAlive(kaChan)
			return <-kaChan
		} else {
			log.Println("Failed to authenticate. Please check the Fortigate address and your username/password then try again")
			return false
		}
	} else {
		return true // Terminate old session and handle new one
	}
}

func main() {
	configure()
	defer logFile.Close()

	go func() { // Graceful exit
		<-exit
		log.Println("Graceful exiting. Have a good day. Bye mate!")
		logFile.Close()
		os.Exit(0)
	}()

	for {
		log.Printf("Dropping old session (%v) to handle new one", cfg.Fit.SessionID)
		if cfg.Fit.SessionID != "" { // Terminate old session to handle new one
			logout()
		}
		if !fit() {
			break
		}
	}

	log.Println("Have a good day. Bye mate!")
}
