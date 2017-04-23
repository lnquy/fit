package utils

import (
	"net/url"
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
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
	if cs, err := oleutil.CallMethod(wshell,
		"CreateShortcut", "%%userprofile%%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
		err != nil {
		return err
	} else {
		idispatch := cs.ToIDispatch()
		oleutil.PutProperty(idispatch, "TargetPath", "./fit.exe")
		oleutil.CallMethod(idispatch, "Save")
	}
	return nil
}
