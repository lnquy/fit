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
		url.QueryEscape(password),
	)
}

// TODO
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
`
	log.Println(banner)
}
