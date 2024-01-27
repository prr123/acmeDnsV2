// createCertsV4.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 5 June 2023
// copyright 2023, 2024 prr, azulsoftware
//
// code copied from V3
// single order for multiple domains
//
// 23 Jan 2024
//

package main

import (
	"log"
	"fmt"
	"os"
	"time"
	"strings"
	"context"

	certLib "acme/acmeDnsV2/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numArgs := len(os.Args)

    flags:=[]string{"dbg","cr","account"}

	useStr := "./createCerts /cr=<crfile> /account=<acnt file> [/dbg]"
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

    // determine whether account file is production (prod) or test    acntval, ok := flagMap["account"]
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

    crFilnam := LEDir + "/csrList/" + crval.(string) + ".cr"
    acntFilnam := LEDir + "/" + acntval.(string) + ".yaml"
	certNam := "cert_" + crval.(string)


    // list of inputs
	// log.Printf("info -- crFilbase:  %s\n", crFilbase)
    log.Printf("info -- crFilnam:   %s\n", crFilnam)
    log.Printf("info -- acntFilnam: %s\n", acntFilnam)
    log.Printf("info -- cert name:  %s\n", certNam)
    log.Printf("info -- prod:       %t\n", prod)
	log.Printf("info -- debug:      %t\n", dbg)

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
	certObj.CertName = certNam

    if dbg {certLib.PrintCertObj(certObj)}

    // creating context
    ctx := context.Background()

	// generate acme client and retrieve let's encrypt account
    err = certObj.GetAcmeClientV2(ctx)
    if err != nil {log.Fatalf("error -- certLib.GetAcmeClient: %v\n", err)}

    if dbg {certLib.PrintClient(certObj.Client)}
    if dbg {certLib.PrintAccount(certObj.LEAccount)}

	// check LE Account
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
	if err != nil {log.Fatalf("error -- found cr domains not in cloudflare domain: IsInZones: %v\n", err)}
	log.Printf("info -- matched all zones!\n")
	if dbg {
		certLib.PrintCrList(CrList)
	}

    // check whether the cr zones have left-over DNS records
	err = certObj.CheckZonesForDNSChalRecords(CrList, ctx)
	if err != nil {log.Fatalf("error -- found old Dns Challenge Records: CheckZoneForDnsRec: %v\n", err)}
	log.Printf("info -- checked zones for Dns challenge records!\n")

	// get authorisation order from Let's Encrypt
	order, err := certObj.GetAuthOrder(CrList, ctx)
	if err != nil {log.Fatalf("error -- GetAuthOrder: %v\n", err)}

	if dbg {certLib.PrintOrder(order)}
	log.Printf("received Authorization Order!\n")
	log.Printf("info -- success!\n")

	// update CRList with authentication info from LE
	// create Dns challenge records on cloudflare's name servers
	CrList, err = certObj.GetAuthFromOrder(CrList, order, ctx)
	if err != nil {log.Fatalf("error -- GetAuthAndToken: %v\n", err)}

	log.Printf("info -- created all dns challenge records!")

	// create a timing loop to check whether probagation was successful
	prob := false
	for i:=0; i< 5; i++ {
		time.Sleep(5*time.Minute)
		log.Printf("time loop [%d]: %s\n", i+1, time.Now().Format(time.RFC1123))
		err = certLib.CheckDnsProbagation(CrList)
		if err != nil {
			errStr := err.Error()
			if idx := strings.Index(errStr, "acme dns rec not yet found"); idx>1 {
				log.Printf("info -- probagation not yet successful!\n")
			} else {
				log.Fatalf("error -- CheckDnsProbagation: %v\n", err)
			}
		} else {
			prob = true
			break
		}
	}

	if !prob {log.Fatalf("error -- could not find Dns Chal recs after 5 wait periods!\n")}

	log.Printf("info -- challenge has probagated: start processing order\n")

	err = certObj.SubmitChallenge(CrList, ctx)
	if err != nil {log.Fatalf("error -- Submit Challenge: %v\n", err)}

	ordUrl := order.URI

	acmeOrder, err := certObj.GetOrderAndWait(ordUrl, ctx)
	if err !=nil {log.Fatalf("error -- WaitGetOrder: %v\n", err)}
	log.Printf("info -- received order\n")
    if certObj.Dbg {certLib.PrintOrder(acmeOrder)}

	certObj.FinalUrl = acmeOrder.FinalizeURL
	log.Printf("info -- FinalUrl: %s\n", certObj.FinalUrl)

	err = certObj.CreateCerts(CrList[0], ctx)
	if err != nil { log.Fatalf("error -- CreateCerts: %v\n", err)}

	log.Printf("info -- success createCerts\n")

    // clean zones
    err = certObj.CleanZonesFromDNSChalRecords(CrList, ctx)
    if err != nil {log.Fatalf("error -- CleanDns: %v\n", err)}
    log.Printf("info -- cleaned zones from Dns challenge records!\n")

}

