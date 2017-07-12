package boot

import (
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/lnquy/fit/utils"
	"log"
	"os"
	"path"
)

func EnableAutoStartup() {
	if err := setStartupShortcut(); err != nil {
		log.Printf("Failed to create startup shortcut for F.IT program on your computer. Error: %s", err)
	} else {
		log.Print("F.IT will automatically start with your computer!")
	}
}

func DisableAutoStartup() {
	lnkPath := path.Join(utils.UserHomeDir(), "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fit.lnk")
	if _, err := os.Stat(lnkPath); !os.IsNotExist(err) {
		if err := os.Remove(lnkPath); err != nil {
			log.Printf("Failed to delete F.IT startup shortcut: %s", lnkPath)
		}
	}
}

func setStartupShortcut() error {
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
	startupMenu := path.Join(utils.UserHomeDir(), "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fit.lnk")
	//log.Printf("User home dir: %s", startupMenu)
	if cs, err := oleutil.CallMethod(wshell, "CreateShortcut", startupMenu); err != nil {
		return err
	} else {
		exePath, _ := os.Executable()
		iDispatch := cs.ToIDispatch()
		oleutil.PutProperty(iDispatch, "TargetPath", exePath)
		oleutil.CallMethod(iDispatch, "Save")
	}
	return nil
}
