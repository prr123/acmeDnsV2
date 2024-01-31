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
//	"time"

	certLib "acme/acmeDnsV2/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)

    flags:=[]string{"dbg","cert"}

	// default file
	dbg := false
    certFilnam := ""

	useStr := "readPemCerts /cert=certfile [/dbg]"
	helpStr := "program that reads a Pem Cert File\n"

	if numarg > 3 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg> 1 && os.Args[1] == "help" {
		fmt.Printf("help:\n%s\n", helpStr)
		fmt.Printf("usage is: %s\n", useStr)
		os.Exit(1)
	}


	flagMap, err := util.ParseFlags(os.Args, flags)
	if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

	_, ok := flagMap["dbg"]
	if ok {dbg = true}
	if dbg {
		for k, v :=range flagMap {
			fmt.Printf("k: %s v: %s\n", k, v)
		}
	}

	certNamVal, ok := flagMap["cert"]
	if ok {
		if certNamVal.(string) == "none" {log.Fatalf("no string provided with /name flag!")}
			certFilnam = certNamVal.(string)
			log.Printf("cert Name: %s\n", certFilnam)
	} else {
		fmt.Printf("help:\n%s\n", helpStr)
		fmt.Printf("usage is: %s\n", useStr)
		log.Fatalf("need cert flag and value\n")
	}

	certObj, err := certLib.InitCertLib()
	if err != nil {log.Fatalf("InitCertLib: %v\n", err)}
    if dbg {certLib.PrintCertObj(certObj)}

	certDir := certObj.CertDir
	if dbg {log.Printf("certDir: %s\n", certDir)}

	certFilnam = certDir + "/" + certFilnam
	log.Printf("full cert file name: %s\n", certFilnam)

	_, err = os.Stat(certFilnam)
	if err != nil {log.Fatalf("cert file with name: %s does not exist: %v\n", certFilnam, err)}

	log.Printf("success reading Certs\n")

	err = certLib.ReadPemCerts(certFilnam, true)
	if err != nil {log.Fatalf("ReadPemCerts: %v\n", err)}


	log.Printf("success parsing Certs\n")

}
