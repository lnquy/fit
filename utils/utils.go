package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	glb "github.com/lnquy/fit/modules/global"
	"github.com/shirou/gopsutil/host"
	"io"
	"log"
	"net/url"
	"strings"
	"time"
)

const (
	defaultUUID string = "#rZy6+s?NL6VB+mp3P63D-3D%h!vkgfV" // Length must be 32
)

func GetFortinetURL(isHttps bool, addr, parm, sId string) (res string) {
	if isHttps {
		res = "https://" + addr + "/" + parm + "?" + sId
	} else {
		res = "http://" + addr + "/" + parm + "?" + sId
	}
	return
}

func GetAuthPostReqData(sId, username, password string) string {
	return fmt.Sprintf("magic=%s&username=%s&password=%s",
		sId,
		url.QueryEscape(username),
		url.QueryEscape(GetPlaintextPassword(password)),
	)
}

func GetProtectedPassword(passwd string) string {
	if cypher, err := encrypt(getUUID(), passwd); err != nil {
		log.Printf("Failed to encrypt your password: %s", err)
		return ""
	} else {
		return fmt.Sprintf("${%s}$", cypher)
	}
}

func GetPlaintextPassword(cypher string) string {
	cypher = strings.TrimSuffix(strings.TrimPrefix(cypher, "${"), "}$")
	if pw, err := decrypt(getUUID(), cypher); err != nil {
		log.Printf("Failed to decrypt your password: %s", err)
		return ""
	} else {
		return string(pw[:])
	}

}

func getUUID() (uuid []byte) {
	if info, err := host.Info(); err != nil {
		return []byte(defaultUUID)
	} else {
		if info.HostID == "" {
			return []byte(defaultUUID)
		}
		return []byte(info.HostID)[:32] // Get the first 32 bytes only
	}
}

func encrypt(key []byte, text string) (string, error) {
	plaintext := []byte(text)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plaintext))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func decrypt(key []byte, cryptoText string) (string, error) {
	cipherText, _ := base64.URLEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("Cyphertext too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return fmt.Sprintf("%s", cipherText), nil
}

func GetTerminationTicker() *time.Ticker {
	now := time.Now()
	nextTick := time.Date(now.Year(), now.Month(), now.Day(), glb.TERM_HOUR, glb.TERM_MIN, glb.TERM_SEC, 0, time.Local)
	if !nextTick.After(now) {
		nextTick = nextTick.Add(time.Hour * 24)
	}
	log.Printf("Auto terminate old session and retrieve new one at: %s", nextTick.String())
	diff := nextTick.Sub(now)
	return time.NewTicker(diff)
}

func PrintBanner() {
	banner := `
    _______        ___   _______
   |       |      |   | |       |
   |    ___|      |   | |_     _|
   |   |___       |   |   |   |
   |    ___| ___  |   |   |   |
   |   |    |   | |   |   |   |
   |___|    |___| |___|   |___|
-------------------------------------
Fortinet Interruption Terminator %s
Contact: Quy Le (lnquy.it@gmail.com)
-------------------------------------`
	log.Printf(banner, glb.FIT_VERSION)
}
