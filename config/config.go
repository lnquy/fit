package config

import (
	"os"
	"encoding/json"
	"log"
)

type FitConfig struct {
	IsHTTPS bool `json:"is_https"`
	Address string `json:"fortinet_address"`
	Username string `json:"username"`
	Password string `json:"password"`
	MaxRetries int `json:"max_retries"`
	RefreshTime int `json:"refresh_time"`

	AutoStartup bool `json:"auto_startup"`
}

var Fit *FitConfig // Configuration singleton

func init() {
	Fit = &FitConfig {
		IsHTTPS: true,
		Address: "192.168.10.1:1003",
		Username: "",
		Password: "",
		MaxRetries: 10,
		RefreshTime: 18000,
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
	return
}
