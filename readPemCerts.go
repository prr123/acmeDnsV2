// readPemCerts.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 23 June 2023
// copyright 2023 prr, azulsoftware
//

package main

import (
	"log"
	"fmt"
	"os"
	"strings"
//	"time"

	certLib "acme/acmeDnsV2/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)

    flags:=[]string{"dbg","cert"}

	useStr := "readPemCerts /cert=certfile [/dbg]"
	helpStr := "program that reads a Pem Cert File"

	if numarg > len(flags) +1 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg> 1 && os.Args[1] == "help" {
		fmt.Printf("help: %s\n", helpStr)
		fmt.Printf("usage: %s\n", useStr)
		os.Exit(0)
	}


	flagMap, err := util.ParseFlags(os.Args, flags)
	if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

	dbg := false
	_, ok := flagMap["dbg"]
	if ok {dbg = true}

	certNamVal, ok := flagMap["cert"]
	if ok {
		if certNamVal.(string) == "none" {log.Fatalf("error -- no string provided with /name flag!")}
	} else {
		log.Fatalf("error -- need cert flag and value\n")
	}
	certName := certNamVal.(string)
	log.Printf("cert Name: %s\n", certName)

	prod := false
	if idx:=strings.Index(certName,"_prod"); idx > -1 {
		prod = true
	} else {
		if idx:=strings.Index(certName,"_test"); idx > -1 {
			prod = false
		} else {
			log.Fatalf("error -- cert name does not contain prod or test!\n")
		}
	}

	certFilnam := certName

	certObj, err := certLib.InitCertLib(dbg, prod)
	if err != nil {log.Fatalf("error -- InitCertLib: %v\n", err)}
    if dbg {certLib.PrintCertObj(certObj)}

	certDir := certObj.CertDir
	if dbg {log.Printf("debug -- certDir: %s\n", certDir)}

	certFilnam = certDir + "/" + certFilnam
	log.Printf("info -- cert file name: %s\n", certFilnam)

	_, err = os.Stat(certFilnam)
	if err != nil {log.Fatalf("error -- cert file with name: %s does not exist: %v\n", certFilnam, err)}

	log.Printf("info -- success locating cert file\n")

	err = certLib.ReadPemCerts(certFilnam, true)
	if err != nil {log.Fatalf("error -- ReadPemCerts: %v\n", err)}

	log.Printf("info -- success parsing Certs\n")
}
