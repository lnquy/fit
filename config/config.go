package config

import (
	"os"
	"encoding/json"
	"log"
)

type FitConfig struct {
	IsHTTPS bool
	Address string
	Username string
	Password string
	MaxRetries int
	RefreshTime int
}

var Fit *FitConfig // Configuration singleton

func init() {
	Fit = &FitConfig {
		IsHTTPS: true,
		Address: "192.168.10.1:1003",
		Username: "",
		Password: "",
		MaxRetries: 10,
		RefreshTime: 1800,
	}
}

func ReadFromFile() (err error) {
	var file *os.File
	if file, err = os.Open("conf.json"); err != nil {
		log.Printf("Open configuration file failed. Error: %s", err)
	} else {
		if err := json.NewDecoder(file).Decode(&F); err != nil {
			log.Printf("Decode configuration file failed. Error: %s", err)
		}
	}
	return
}
