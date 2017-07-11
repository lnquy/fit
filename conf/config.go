package conf

import (
	"os"
	"encoding/json"
	"log"
	"io/ioutil"
	glb "github.com/lnquy/fit/modules/global"
)

type FitConfig struct {
	IsHTTPS bool `json:"is_https"`
	Address string `json:"fortinet_address"`
	Username string `json:"username"`
	Password string `json:"password"`
	MaxRetries int `json:"max_retries"`
	RefreshTime int `json:"refresh_time"`

	AutoStartup bool `json:"auto_startup"`
	SessionID string `json:"session_id"`
}

var Fit *FitConfig // Configuration singleton

func init() {
	Fit = &FitConfig {
		IsHTTPS: true,
		Address: glb.DEFAULT_FORTINET_ADDR,
		Username: "",
		Password: "",
		MaxRetries: glb.DEFAULT_MAX_RETRIES,
		RefreshTime: glb.DEFAULT_REFRESH_TIME,
		AutoStartup: false,
		SessionID: "",
	}
}

func ReadFromFile() (err error) {
	var file *os.File
	if file, err = os.Open("fit.conf"); err != nil {
		log.Printf("Open configuration file failed. Error: %s", err)
	} else {
		if err := json.NewDecoder(file).Decode(&Fit); err != nil {
			log.Printf("Decode configuration file failed. Error: %s", err)
		}
	}
	defer file.Close()
	return
}

func WriteToFile() (err error) {
	fitConfig, _ := json.MarshalIndent(Fit, "", "    ")
	return ioutil.WriteFile("fit.conf", fitConfig, 0666)
}