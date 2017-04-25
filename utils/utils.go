package utils

import (
	"net/url"
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"os"
	"runtime"
	"path"
	"log"
	"github.com/lnquy/fit/config"
	"github.com/shirou/gopsutil/host"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"
)

const (
	defaultUUID string = "SuP3R%sTR0nG@SecR3t&K3Y^743#032#" // Length must be 32
)

func GetFortinetURL(isHttps bool, addr, parm, sId string) (res string) {
	if isHttps {
		res = "https://" + addr + "/" + parm + "?" + sId
	} else {
		res = "http://" + addr + "/" + parm + "?" + sId
	}
	return
}

func GetAuthPostReqData(sId, username, password string) (string) {
	return fmt.Sprintf("magic=%s&username=%s&password=%s",
		sId,
		url.QueryEscape(username),
		url.QueryEscape(GetPlaintextPassword(password)),
	)
}

func SetStartupShortcut() error {
	ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED|ole.COINIT_SPEED_OVER_MEMORY)
	oleShellObject, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return err
	}
	defer oleShellObject.Release()
	wshell, err := oleShellObject.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer wshell.Release()
	// Note: For Windows only, not supported for Unix yet
	startupMenu := path.Join(UserHomeDir(), "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fit.lnk")
	//log.Printf("user home dir: %s", startupMenu)
	if cs, err := oleutil.CallMethod(wshell, "CreateShortcut", startupMenu); err != nil {
		return err
	} else {
		exePath, _ := os.Executable()
		idispatch := cs.ToIDispatch()
		oleutil.PutProperty(idispatch, "TargetPath", exePath)
		oleutil.CallMethod(idispatch, "Save")
	}
	return nil
}

func UserHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func ProtectPassword(c *config.FitConfig) {
	key := getUUID()
	if cypher, err := encrypt([]byte(key), c.Password); err != nil {
		log.Println("[Config] Cannot encrypt your password. Your password in configuration file will be remained as plaintext :(", err)
		return
	} else {
		c.Password = fmt.Sprintf("${%s}$", cypher)
	}

	if err := config.WriteToFile(); err != nil {
		log.Println("[Config] Cannot write encrypted password to file. Your password in configuration file will be remained as plaintext :(", err)
	} else {
		log.Println("[Config] Your password has been encrypted automatically :)")
	}
}

func GetPlaintextPassword(cypher string) string {
	key := getUUID()
	cypher = strings.TrimSuffix(strings.TrimPrefix(cypher, "${"), "}$")
	if pw, err := decrypt([]byte(key), cypher); err != nil {
		log.Printf("Cannot decrypt your password. Error: %s", err)
		return ""
	} else {
		return string(pw[:])
	}

}

func getUUID() (uuid string) {
	if info, err := host.Info(); err != nil {
		log.Println("Cannot get host UUID. Will use default secret key to encrypt your password")
		return defaultUUID
	} else {
		if info.HostID == "" {
			return defaultUUID
		}
		return info.HostID[:32] // Get the first 32 bytes only
	}
}

func encrypt(key []byte, text string) (string, error) {
	plaintext := []byte(text)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
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

Fortinet Interruption Terminator
lnquy.it@gmail.com
--------------------------------`
	log.Println(banner)
}
