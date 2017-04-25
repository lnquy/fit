package main

import (
	"github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
	"fmt"
)
func main() {
	v1 := uuid.NewV1()
	v3 := uuid.NewV3(uuid.NamespaceURL, "localhost")
	v4 := uuid.NewV4()
	v5 := uuid.NewV5(uuid.NamespaceURL, "localhost")

	var info *host.InfoStat
	var err error
	if info, err = host.Info(); err != nil {
		fmt.Printf("cannot get host info. Error: %s", err)
	}

	fmt.Printf("V1: %s\nV3: %v\nV4: %s\nV5: %v\n", v1, v3, v4, v5)
	fmt.Printf("Host Info: %v", info)
}
