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

    // list of inputs
	// log.Printf("info -- crFilbase:  %s\n", crFilbase)
    log.Printf("info -- crFilnam:   %s\n", crFilnam)
    log.Printf("info -- acntFilnam: %s\n", acntFilnam)
    log.Printf("info -- prod:  %t\n", prod)
    log.Printf("info -- debug: %t\n", dbg)

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
	if dbg {
		certLib.PrintCrList(CrList)
	}

    // check whether the cr zones have left-over DNS records
	err = certObj.CheckZonesForDNSChalRecords(CrList, ctx)
	if err != nil {log.Fatalf("error -- CheckZoneForDnsRec: %v\n", err)}
	log.Printf("info -- checked zones for Dns challenge records!\n")

	newOrder, err := certObj.GetAuthOrder(CrList, ctx)
	if err != nil {log.Fatalf("error -- GetAuthOrder: %v\n", err)}

	if dbg {certLib.PrintOrder(*newOrder)}
	log.Printf("received Authorization Order!\n")
	log.Printf("info -- success!\n")

	CrList, err = certObj.GetAuthAndToken(CrList, newOrder, ctx)
	if err != nil {log.Fatalf("error -- GetAuthAndToken: %v\n", err)}

	log.Printf("info -- created all dns challenge records!")

	// create a timing llop to check whether probagation was successful
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

	if !prob {log.Fatalf("error -- could not find Dns Chal recs  after 5 wait periods!\n")}

	// Next Step: create Certs


	log.Printf("info -- success createCerts\n")


	log.Printf("info -- arrived at ProcOrd\n")


	err = certObj.SubmitChallenge(CrList, ctx)
	if err != nil {log.Fatalf("error -- Submit Challenge: %v\n", err)}
/*
	// ready for sending an accept; checked dns propogation with lookup
	for i:=0; i< numAcmeDom; i++ {
//		dom := csrList.Domains[i]
//        csrList.Domains[i].Token = chal.Token
//        csrList.Domains[i].TokUrl = chal.URI

		chalVal := acme.Challenge{
			Type: "dns-01",
			URI: dom.TokUrl,
			Token: dom.Token,
			Status: "pending",
		}
		if dbg {certLib.PrintChallenge(&chalVal, dom.Domain)}

		domain := dom.Domain
		log.Printf("sending Accept for domain %s\n", domain)

		chal, err := client.Accept(ctx, &chalVal)
		if err != nil {log.Fatalf("dns-01 chal not accepted for %s: %v", domain, err)}
		if dbg {certLib.PrintChallenge(chal, domain)}
 		log.Printf("chal accepted for domain %s\n", domain)

	}
*/

	ordUrl := newOrder.URI

	err = certObj.GetOrder(ordUrl, ctx)
	if err !=nil {log.Fatalf("error -- GetOrder: %v\n", err)}
}

	/*
	tmpord, err := client.GetOrder(ctx, ordUrl)
	if err !=nil {log.Fatalf("order error: %v\n", err)}
	if dbg {certLib.PrintOrder(*tmpord)}

    log.Printf("waiting for order\n")
	if dbg {log.Printf("order url: %s\n", ordUrl)}

    ordUrl2, err := client.WaitOrder(ctx, ordUrl)
    if err != nil {
		if ordUrl2 != nil {certLib.PrintOrder(*ordUrl2)}
		log.Fatalf("client.WaitOrder: %v\n",err)
	}
	log.Printf("received order!\n")
	if dbg {certLib.PrintOrder(*ordUrl2)}

	csrData := csrList.Domains[0]

		//certLib.PrintCsr(csrData)
	domain := csrData.Domain
	log.Printf("generating certificate for domain: %s\n", domain)
		// get certificates
	certNam, err :=certLib.GenerateCertName(domain)
	if err != nil {log.Fatalf("GenerateCertName: %v", err)}
	if dbg {log.Printf("certNam: %s\n", certNam)}

	keyFilnam := certObj.CertDir + "/" + certNam + ".key"
	certFilnam := certObj.CertDir + "/" + certNam + ".crt"
	log.Printf("key file: %s cert file: %s\n", keyFilnam, certFilnam)

//	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certKey, err := certLib.GenCertKey()
	if err != nil {
		log.Fatalf("GenCertKey: %v\n",err)
	}
	log.Printf("Cert Request: key generated!\n")

	err = certLib.SaveKeyPem(certKey, keyFilnam)
	if err != nil {log.Fatalf("certLib.SaveKeypem: %v",err)}
	log.Printf("Save: key saved as PEM!\n")

	csrTpl, err := certLib.CreateCsrTplNew(csrList, -1)
	if err != nil {	log.Fatalf("CreateCsrTpl: %v",err)}

//	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTpl, certKey)
//	if err != nil {	log.Fatalf("CreateCertReq: %v",err)}

	csr, err := certLib.CreateCsr(csrTpl, certKey)
	if err != nil {	log.Fatalf("CreateCertReq: %v",err)}

	csrParseReq, err := certLib.ParseCsr(csr)
	if err != nil {log.Fatalf("Error parsing certificate request: %v", err)}

	// need to compare csrParse and template
	certLib.PrintCsrReq(csrParseReq)

	FinalUrl := ordUrl2.FinalizeURL
	log.Printf("FinalUrl: %s\n", FinalUrl)

	derCerts, certUrl, err := client.CreateOrderCert(ctx, FinalUrl, csr, true)
	if err != nil {log.Fatalf("CreateOrderCert: %v\n",err)}

	if dbg {log.Printf("derCerts: %d certUrl: %s\n", len(derCerts), certUrl)}

	csrList.CertUrl = certUrl
	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", certFilnam)

	err = certLib.SaveCertsPem(derCerts, certFilnam)
	if err != nil {log.Fatalf("SaveCerts: %v\n",err)}

	// cleanup
	for i:=0; i< numAcmeDom; i++ {
		acmeZone := acmeDomList[i]
		acmeZone.AcmeId = csrList.Domains[i].ChalRecId

		err = cfApiObj.DelDnsChalRecord(acmeZone)
    	if err != nil {log.Fatalf("DelDnsChalRecord: %v\n",err)}
		log.Printf("deleted DNS Chal Record for zone: %s\n", acmeZone.Name)
	}

	if dbg {certLib.PrintCsrList(csrList) }
	err = certLib.CleanCsrFil(csrFilnam, csrList)
	if err != nil {log.Fatalf("CleanCsrFil: %v\n",err)}
	log.Printf("success writing Csr File\n")

	log.Printf("success creating Certs\n")
}
*/
