package utils

import (
	"net/url"
	"fmt"
)


func GetFortinetURL(isHttps bool, addr, parm, sId string) (res string) {
	if isHttps {
		res = "https://" + addr + "/" + parm + "?" + sId
	} else {
		res = "http://" + addr + "/" + parm + "?" + sId
	}
	return
}

func GetAuthPostReqData(sId , username, password string) (string) {
	return fmt.Sprintf("magic=%s&username=%s&password=%s",
		sId,
		url.QueryEscape(username),
		url.QueryEscape(password),
	)
}
