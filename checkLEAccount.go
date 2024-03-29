// checkAcnt.go
// program that generates Lets encrypt Account and saves keys
// author: prr azul software
// date: 8 May 2023
// copyright 2023 prr, azulsoftware
//
// refactored 22 Jan 2024

package main

import (

	"log"
	"fmt"
	"os"
	"strings"
	"context"

    util "github.com/prr123/utility/utilLib"
	certLib "acme/acmeDnsV2/certLib"
//    yaml "github.com/goccy/go-yaml"
)


func main() {

	numarg := len(os.Args)

	useStr := "/acnt=name /type=[prod|test] [/dbg]"
	helpStr:= "program that cheecks validity of LEAccount!"

    flags:=[]string{"dbg","acnt", "type"}

	if numarg > len(flags) + 1 {
		fmt.Printf("usage: %s %s\n", os.Args[0], useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(0)
	}

	if numarg >1 && os.Args[1] == "help" {
		fmt.Printf("help: %s\n", helpStr)
		fmt.Printf("usage: %s %s\n", os.Args[0], useStr)
		os.Exit(0)
	}

    flagMap, err := util.ParseFlags(os.Args, flags)
    if err != nil {log.Fatalf("error -- util.ParseFlags: %v\n", err)}

	dbg := false
    _, ok := flagMap["dbg"]
    if ok {dbg = true}

	acntNam := ""
    acntval, ok := flagMap["acnt"]
    if ok {
        if acntval.(string) == "none" {log.Fatalf("error -- no account name provided with /acnt flag!\n")}
        acntNam = acntval.(string)
    } else {
        log.Fatalf("error -- no /acnt flag provided!\n")
    }

	prod := false
    tval, ok := flagMap["type"]
    if ok {
        if tval.(string) == "none" {log.Fatalf("error -- no type value provided for  /type flag!\n")}
		if idx := strings.Index(tval.(string), "."); idx > -1 {
			log.Fatalf("error -- invalid acnt value: contains period!")
		}
		switch tval.(string) {
			case "prod":
				acntNam = acntval.(string) + "_prod.yaml"
				prod = true
			case "test":
				acntNam = acntval.(string) + "_test.yaml"
			default:
				log.Fatalf("error -- invalid type: %s!\n", tval.(string))
		}
    } else {
        log.Fatalf("error -- no /type flag provided!\n")
    }

	log.Printf("info -- debug: %t\n", dbg)
	if prod {
		log.Printf("info -- production!\n")
	} else {
		log.Printf("info -- testing!\n")
	}
	log.Printf("info -- account file: %s\n", acntNam)


	LEDir := os.Getenv("LEDir")
	if len(LEDir) == 0 {log.Fatalf("error -- could not retrieve env var LEDir!\n")}

    acntFilnam := LEDir + "/" + acntNam

	// creating context
	ctx := context.Background()


	certObj, err := certLib.InitCertLib(dbg, prod)
	if err != nil {log.Fatalf("error -- certLib.InitCertLib: %v\n", err)}
	certObj.AcntFilnam = acntFilnam
	if dbg {
		log.Printf("debug -- CertObj after Init\n")
		certObj.PrintCertObj()
	}

	err = certObj.GetAcmeClientV2(ctx)
	if err != nil {log.Fatalf("error -- certLib.GetAcmeClientV2: %v\n", err)}

	if dbg {
		log.Printf("debug -- CertObj after GetAcmeClient\n")
		certObj.PrintCertObj()
	}

	if dbg {certLib.PrintClient(certObj.Client)}
	acnt:= certObj.LEAccount
	if dbg {certLib.PrintAccount(acnt)}

	if acnt.Status == "valid" {
		log.Printf("info -- account is valid!\n")
	} else {
		log.Fatalf("error -- acount is not valid. status: %s\n", acnt.Status)
	}

	log.Printf("info -- success!\n")
}
