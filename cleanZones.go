// cleanZones.go
// program that removes leftover DNS challenge records from zones
// author: prr azul software
// date: 25 Jan 2024
// copyright 2024 prr, azulsoftware
//
//

package main

import (
	"log"
	"fmt"
	"os"
//	"time"
//	"net"
	"strings"
	"context"
//	"golang.org/x/crypto/acme"

	certLib "acme/acmeDnsV2/certLib"
//    cfLib "acme/acmeDnsV2/cfLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numArgs := len(os.Args)

    flags:=[]string{"dbg","cr","account"}

	useStr := "./cleanZones /cr=<crfile> /account=<acnt file> [/dbg]"
	helpStr := "program that creates one certificate for all domains listed in the file csrList.yaml\n"
	helpStr += "requirements: - a file listing all cloudflare domains/zones controlled by this account\n"
	helpStr += "              - a cloudflare authorisation file with a token that permits DNS record changes in the direcory cloudflare/token\n"
	helpStr += "              - a csr yaml file located in $LEAcnt/csrList\n"

	if numArgs > len(flags) + 1 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numArgs == 1 || (numArgs>1 && os.Args[1] == "help") {
		fmt.Printf("help: %s\n", helpStr)
		fmt.Printf("usage is: %s\n", useStr)
		os.Exit(-1)
	}

	flagMap, err := util.ParseFlags(os.Args, flags)
	if err != nil {log.Fatalf("error -- util.ParseFlags: %v\n", err)}

	dbg := false
	_, ok := flagMap["dbg"]
	if ok {dbg = true}

    crval, ok := flagMap["cr"]
    if !ok {log.Fatalf("error -- /cr flag not present!\n")}
    if crval.(string) == "none" {log.Fatalf("error -- no cr file provided with /cr flag!\n")}
    if idx := strings.Index(crval.(string), "."); idx > -1 {
        log.Fatalf("error -- cr name has an extension!\n")
    }
    if idx := strings.Index(crval.(string), "_"); idx == -1 {
        log.Fatalf("error -- cr name has no tld!\n")
    }

	// determine whether account file is production (prod) or test
    acntval, ok := flagMap["account"]
    if !ok {log.Fatalf("error -- /account flag not present!\n")}
    if acntval.(string) == "none" {log.Fatalf("error -- no file provided with /account flag!\n")}
    idx := strings.Index(acntval.(string), "_")
	if idx == -1 {
        log.Fatalf("error -- account name has not type !\n")
    }
	typStr := string(acntval.(string)[idx +1:])
	if dbg {log.Printf("debug -- typeStr: %s\n", typStr)}

	prod:= true
	switch typStr {
		case "prod":
			prod = true
		case "test":
			prod = false
		default:
			log.Fatalf("error -- account name has invalid type: %s\n", typStr)
	}

    LEDir := os.Getenv("LEDir")
    if len(LEDir) == 0 {log.Fatalf("error -- cannot retrieve env var LEDir!\n")}

	// cr: certificate request
    crFilnam := LEDir + "/csrList/" + crval.(string) + ".cr"
    acntFilnam := LEDir + "/" + acntval.(string) + ".yaml"

	// list of inputs
//    log.Printf("info -- crFilbase:  %s\n", crFilbase)
    log.Printf("info -- crFilnam:   %s\n", crFilnam)
    log.Printf("info -- acntFilnam: %s\n", acntFilnam)
    log.Printf("info -- prod:  %t\n", prod)
    log.Printf("info -- debug: %t\n", dbg)

	// get list of zones that will be covered by the requested certificate
    CrList, err := certLib.ReadCrFile(crFilnam)
    if err != nil {log.Fatalf("error -- ReadCrFile: %v\n", err)}

	if dbg {
		log.Printf("debug -- Domains[%d]\n", len(CrList))
		for i:=0; i< len(CrList); i++ {
			certLib.PrintCr(CrList[i])
		}
	}

	// may refactor the certObj
	certObj, err := certLib.InitCertLib(dbg, prod)
	if err != nil {log.Fatalf("error -- InitCertLib: %v\n", err)}
	certObj.AcntFilnam = acntFilnam

    if dbg {certLib.PrintCertObj(certObj)}

    // creating context
    ctx := context.Background()


    err = certObj.GetAcmeClientV2(ctx)
    if err != nil {log.Fatalf("error -- certLib.GetAcmeClient: %v\n", err)}

    if dbg {certLib.PrintClient(certObj.Client)}
    if dbg {certLib.PrintAccount(certObj.LEAccount)}

    if certObj.LEAccount.Status == "valid" {
        log.Printf("info -- account is valid!\n")
    } else {
        log.Fatalf("error -- acount is not valid. status: %s\n", certObj.LEAccount.Status)
    }

	// get list of cloudflare managed zones
    zones, err := certObj.GetCfZoneList(ctx)
    if err != nil {log.Fatalf("error -- GetZoneList: %v\n", err)}

    log.Printf("info -- zones: %d\n", len(zones))

    if dbg {certLib.PrintZones(zones)}

	// check whether all cr zones are contained in the cloudflare list
	CrList, err = certLib.IsInZones(zones, CrList)
	if err != nil {log.Fatalf("error -- IsInZones: %v\n", err)}
	log.Printf("info -- matched all zones!\n")

	// check whether the cr zones have left-over DNS records
    err = certObj.CheckZonesForDNSChalRecords(CrList, ctx)
    if err == nil {
		log.Printf("info -- no Zones with Dns challenge records!\n")
		os.Exit(0)
	}
	log.Printf("info -- found zones with DNS challenge records: %v\n", err)

	// clean zones
	err = certObj.CleanZonesFromDNSChalRecords(CrList, ctx)
	if err != nil {log.Fatalf("error -- CleanDns: %v\n", err)}
	log.Printf("info -- cleaned zones from Dns challenge records!\n")


	log.Printf("info -- success!\n")
}

