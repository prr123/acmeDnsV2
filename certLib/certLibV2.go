// certLibV2.go
// library that support the generation of certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 29 April 2023
// copyright 2023 prr, azulsoftware
//
// refactored 22 Jan 2024
//

package certLib

import (
    "log"
    "fmt"
    "os"
    "time"
    "context"
	"strings"
	"net"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"

   "golang.org/x/crypto/acme"
    "github.com/cloudflare/cloudflare-go"
    yaml "github.com/goccy/go-yaml"
    json "github.com/goccy/go-json"
)

const LEProdUrl = "https://acme-v02.api.letsencrypt.org/directory"
const LETestUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"

type AccountInfo struct {
	Name string `yaml:"Name"`
	Contacts []string `yaml:"Contacts"`
}

type LEObj struct {
	AcntNam string `yaml:"AcntName"`
	AcntId string `yaml:"AcntId"`
	PrivKeyFilnam string `yaml:"PrivKeyFilnam"`
	PubKeyFilnam string `yaml:"PubKeyFilnam"`
	Updated time.Time `yaml:"update"`
	Contacts []string `yaml:"contacts"`
	Type string `yaml:"AcntType:"`
	LEUrl string `yaml:"LEUrl"`
}

/*
type CsrList struct {
    AcntName string `yaml:"account"`
	LastLU time.Time `yaml:"last"`
	OrderUrl string `yaml:"orderUrl"`
	CertUrl string `yaml:"certUrl"`
    Domains []CsrDat `yaml:"domains"`
}

type CsrDat struct {
    Domain string `yaml:"domain"`
    Email string `yaml:"email"`
    PemFil string `yaml:"pemfil"`
	ChalRecId string `yaml:"chalrec"`
	Token	string `yaml:"token"`
	TokVal string `yaml:"tokval"`
	TokUrl string `yaml:"tokUrl"`
	TokIssue time.Time `yaml:"issue"`
	TokExp time.Time `yaml:"expire"`
	OrderUrl string `yaml:"orderUrl"`
	CertUrl string `yaml:"certUrl"`
    Name pkixName `yaml:"Name"`
}
*/
type CertList struct {
	CertNam string `yaml:"certName"`
	Domains []string `yaml:"domains"`
	LEUrl string	`yaml:"LEUrl"`
	Valid	time.Time	`yaml:"valid"`
	Expire time.Time	`yaml:"expire"`
}

type pkixName struct {
    CommonName string `yaml:"Domain"`
    Country string `yaml:"Country"`
    Province string `yaml:"Province"`
    Locality string `yaml:"Locality"`
    Organisation string `yaml:"Organisation"`
    OrganisationUnit string `yaml:"OrganisationUnit"`
}

type CrObj struct {
	CrFilnam string `yaml:"CrFilnam"`
    Zone string `yaml:"Domain"`
	ZoneId string `yaml:"ZoneId"`
	Email string `yaml:"Email"`
	Start time.Time `yaml:"Start"`
    Country string `yaml:"Country"`
    Province string `yaml:"Province"`
    Locality string `yaml:"Locality"`
    Organisation string `yaml:"Organisation"`
    OrganisationUnit string `yaml:"OrganisationUnit"`
	CertName string `yaml:"CertName"`
	CertUrl string `yaml:"CertUrl"`
	CertFilnam string `yaml:"CertFilnam"`
	CertExp time.Time `yaml:"CertExpirary"`
	token string
	tokURI string
}


type CertObj struct {
	ZoneDir string
	CertDir string
	CertName string
	CertFilnam string
	ZoneFilnam string
	AcntFilnam string
	FinalUrl string
	CertUrl string
	LeDir string
	CfDir string
	CsrDir string
	CfToken string
	Dbg	bool
	Prod bool
	Client *acme.Client
	LEAccount *acme.Account
	api *cloudflare.API
}



// yaml version of type acme.Account
type JsAcnt struct {
    // URI is the account unique ID, which is also a URL used to retrieve
    // account data from the CA.
    // When interfacing with RFC 8555-compliant CAs, URI is the "kid" field
    // value in JWS signed requests.
    URI string `yaml: "URI"`

    // Contact is a slice of contact info used during registration.
    // See https://tools.ietf.org/html/rfc8555#section-7.3 for supported
    // formats.
    Contact []string `yaml: "Contact"`

    // Status indicates current account status as returned by the CA.
    // Possible values are StatusValid, StatusDeactivated, and StatusRevoked.
    Status string `yaml: "Status"`

    // OrdersURL is a URL from which a list of orders submitted by this account
    // can be fetched.
    OrdersURL string `yaml: "OrdersURL"`

    // The terms user has agreed to.
    // A value not matching CurrentTerms indicates that the user hasn't agreed
    // to the actual Terms of Service of the CA.
    //
    // It is non-RFC 8555 compliant. Package users can store the ToS they agree to
    // during Client's Register call in the prompt callback function.
    AgreedTerms string `yaml: "Terms"`

    // Actual terms of a CA.
    //
    // It is non-RFC 8555 compliant. Use Directory's Terms field.
    // When a CA updates their terms and requires an account agreement,
    // a URL at which instructions to do so is available in Error's Instance field.
    CurrentTerms string `yaml: "CurTerms"`

    // Authz is the authorization URL used to initiate a new authz flow.
    //
    // It is non-RFC 8555 compliant. Use Directory's AuthzURL or OrderURL.
    Authz string `yaml: "Authz"`

    // Authorizations is a URI from which a list of authorizations
    // granted to this account can be fetched via a GET request.
    //
    // It is non-RFC 8555 compliant and is obsoleted by OrdersURL.
    Authorizations string `yaml: "Auth"`
    // Certificates is a URI from which a list of certificates
    // issued for this account can be fetched via a GET request.
    //
    // It is non-RFC 8555 compliant and is obsoleted by OrdersURL.
    Certificates string `yaml: "Certs"`

    // ExternalAccountBinding represents an arbitrary binding to an account of
    // the CA which the ACME server is tied to.
    // See https://tools.ietf.org/html/rfc8555#section-7.3.4 for more details.
    ExternalAccountBinding *acme.ExternalAccountBinding `yaml: "ExtAcct"`
}


func InitCertLib(dbg, prod bool)(certobj *CertObj, err error) {
	certObj := CertObj{}
	certObj.Dbg = dbg
	certObj.Prod = prod

    leDir := os.Getenv("LEDir")
    if len(leDir) < 1 {return nil, fmt.Errorf("could not resolve env var LEDir!")}
	certObj.LeDir = leDir
//    csrFilnam := leAcnt + "csrList/csrTest.yaml"
	certObj.CertDir = leDir + "/certs"

    cfDir := os.Getenv("cfDir")
    if len(cfDir) == 0 {return nil, fmt.Errorf("could not resolve env var cfDir!")}
	certObj.CfDir = cfDir
    certObj.CfToken = cfDir + "/token/DnsWrite.json"
	certObj.ZoneDir = cfDir + "/zones"

	certObj.CsrDir = leDir + "/csrList/"

	// get cloudflare DnsWrite Token
    rdTokFilnam := cfDir + "/token/DnsWrite.json"

    bdat, err := os.ReadFile(rdTokFilnam)
    if err != nil {return nil, fmt.Errorf("cannot read token file: %v\n", err)}

    ZoneTok := cloudflare.APIToken {}
    err = json.Unmarshal(bdat, &ZoneTok)
    if err != nil {return nil, fmt.Errorf("cannot unmarshal token file: %v\n", err)}

	// get cloudflare api
    api, err := cloudflare.NewWithAPIToken(ZoneTok.Value)
	if err != nil {return nil, fmt.Errorf("getting cf api obj: %v",err)}
	certObj.api = api

	return &certObj, nil
}


func ReadCrFile(filnam string)(Cr []CrObj, err error) {

    crdat, err := os.ReadFile(filnam)
    if err != nil {return Cr, fmt.Errorf("read cr file: %v\n", err)}
//    fmt.Printf("crdat: %s\n", crdat)

	err = yaml.Unmarshal(crdat, &Cr)
	if err != nil {return Cr, fmt.Errorf("CR Unmarshal: %v", err)}

	noTime, _ := time.Parse(time.RFC822, "01 Jan 0001 00:00:00 UTC")

	for i:=0; i< len(Cr); i++ {
//	fmt.Printf("no time: %s\n", noTime.Format(time.RFC1123))
		if Cr[i].Start.Sub(noTime) == 0  {Cr[i].Start = time.Now()}
	}

	return Cr, nil
}


func (certobj *CertObj) WriteCrFinalFile(Cr []CrObj)(err error) {

	Cr[0].CertUrl = certobj.CertUrl
	Cr[0].CertName = certobj.CertName
//	Cr[0].CertExp = time
	filnam := certobj.CsrDir + "/" + certobj.CertName + ".crf"

	fdat, err := yaml.Marshal(&Cr)
	if err != nil {return fmt.Errorf("marshal: %v\n", err)}

	err = os.WriteFile(filnam, fdat, 0600)
	if err != nil {return fmt.Errorf("write file: %v\n", err)}

	return nil
}

func IsInZones(zones []cloudflare.Zone, CrList []CrObj) (NCrList[]CrObj, err error) {

	log.Printf("info -- zones: %d\n", len(zones))
	log.Printf("info -- CRList: %d\n", len(CrList))

	match := false
	for i:=0; i< len(CrList); i++ {
		tgtZone := CrList[i]
		fmt.Printf(" %d: %s\n", i+1, tgtZone.Zone)
		idx := -1
		for j:=0; j< len(zones); j++ {
			if zones[j].Name == tgtZone.Zone {
				CrList[i].ZoneId = zones[j].ID
				match = true
				idx = j
				break
			}
		}
		if idx == -1 { return CrList, fmt.Errorf("no match for zone: %s", tgtZone.Zone)}
	}

	if !match {return CrList, fmt.Errorf("no match found!")}
	return CrList, nil
}

//uuu

func (certobj *CertObj)CheckZonesForDNSChalRecords(crList []CrObj, ctx context.Context) (err error) {

	api := certobj.api

    rc := cloudflare.ResourceContainer{
        Level: cloudflare.ZoneRouteLevel,
//        Identifier: zoneId,
    }

    DnsPar:=cloudflare.ListDNSRecordsParams{
		Type: "TXT",
	}

	for i:=0; i< len(crList); i++ {
		acmeDomain := "_acme-challenge." + crList[i].Zone
		if len(crList[i].ZoneId) == 0 {return fmt.Errorf("Zone[%d] %s has no Id!\n", i+1, crList[i].Zone)}

		rc.Identifier = crList[i].ZoneId
		DnsPar.Name = acmeDomain

		// check cloudflare name servers
		DnsRecList, _, err := api.ListDNSRecords(ctx, &rc, DnsPar)
		if err != nil { return fmt.Errorf("Zone[%d] %s ListDnsRec: %v!\n", i+1, crList[i].Zone, err)}
		if len(DnsRecList) > 0 {return fmt.Errorf("Zone[%d] %s found challenge record!\n", i+1, crList[i].Zone)}

		// for probgated records
		_, err = net.LookupTXT(acmeDomain)
		if err != nil {
            errStr := err.Error()
//			fmt.Printf("lookup: %s\n", errStr)
            idx := strings.Index(errStr, "no such host")
//			fmt.Printf("idx: %d\n", idx)
			if idx == -1 {
				return fmt.Errorf("Lookup Zone %s: %v", crList[i].Zone, err)
            }
		}
	}

	return nil
}


func (certobj *CertObj) GetCfZoneList(ctx context.Context) (zones []cloudflare.Zone,err error){

	api := certobj.api

	zones, err = api.ListZones(ctx)
    if err != nil {return zones, fmt.Errorf("error -- cannot get zones: %v\n", err)}

    return zones, nil
}

func (certobj *CertObj) SubmitChallenge(crList []CrObj, ctx context.Context) (err error) {

	client := certobj.Client

	chalVal := acme.Challenge{
		Type: "dns-01",
//		URI: dom.TokUrl,
//		Token: dom.Token,
		Status: "pending",
	}


	for i:=0; i< len(crList); i++ {

		domain := crList[i].Zone
		chalVal.URI = crList[i].tokURI
		chalVal.Token = crList[i].token

        chal, err := client.Accept(ctx, &chalVal)
        if err != nil {return fmt.Errorf("dns-01 chal not accepted for %s: %v", domain, err)}
        if certobj.Dbg {PrintChallenge(chal, domain)}
	}

	return nil
}

func (certobj *CertObj) GetOrderAndWait(ordUrl string, ctx context.Context)(ordUrlNew *acme.Order, err error) {

	client := certobj.Client

   	tmpord, err := client.GetOrder(ctx, ordUrl)
    if err !=nil {return nil, fmt.Errorf("order error: %v\n", err)}
    if certobj.Dbg {PrintOrder(tmpord)}

    acmeOrder, err := client.WaitOrder(ctx, ordUrl)
    if err != nil {
        if acmeOrder != nil {PrintOrder(acmeOrder)}
        return acmeOrder, fmt.Errorf("client.WaitOrder: %v\n",err)
    }

	return acmeOrder, nil
}

func (certobj *CertObj) CreateCerts(cr CrObj, ctx context.Context)(err error) {

//certNam string, FinalUrl string 

	client := certobj.Client

    certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {return fmt.Errorf("ecdsa.GenerateKey: %v\n",err)}

	keyFilnam := certobj.CertDir + "/" + certobj.CertName + ".key"
    certFilnam := certobj.CertDir + "/" + certobj.CertName + ".crt"
	if certobj.Dbg {log.Printf("debug --- key file: %s cert file: %s\n", keyFilnam, certFilnam)}

    err = SaveKeyPem(certKey, keyFilnam)
    if err != nil {return fmt.Errorf("error -- certLib.SaveKeypem: %v",err)}
    if certobj.Dbg {log.Printf("debug -- key saved as PEM!\n")}

	// need to create a csr template(certifcate signing request)
    subj := pkix.Name{
        CommonName:         cr.Zone,
        Country:            []string{cr.Country},
        Province:           []string{cr.Province},
        Locality:           []string{cr.Locality},
        Organization:       []string{cr.Organisation},
        OrganizationalUnit: []string{"Admin"},
    }

    rawSubj := subj.ToRDNSequence()
    asn1Subj, _ := asn1.Marshal(rawSubj)

	csrTpl := x509.CertificateRequest{
        RawSubject:         asn1Subj,
        SignatureAlgorithm: x509.ECDSAWithSHA256,
        DNSNames: []string{cr.Zone},
    }
	if certobj.Dbg {
		log.Printf("debug: csr template:\n")
		PrintCsr(&csrTpl)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTpl, certKey)
	if err != nil {return fmt.Errorf("CreateCertReq: %v",err)}

	certReq, err := x509.ParseCertificateRequest(csr)
	if err != nil {return fmt.Errorf("ParseCertificateRequest: %v", err)}
	if certobj.Dbg {
		log.Printf("debug -- success Parse Cert Req!\n")
		PrintCsr(certReq)
	}

	err = certReq.CheckSignature()
	if err != nil {return fmt.Errorf("invalid signature of cert req!")}
	if certobj.Dbg {log.Printf("debug -- signature check was successful!\n")}

    derCerts, certUrl, err := client.CreateOrderCert(ctx, certobj.FinalUrl, csr, true)
    if err != nil {return fmt.Errorf("CreateOrderCert: %v\n",err)}

	if certobj.Dbg {log.Printf("debug -- success obtained derCerts: %d certUrl: %s\n", len(derCerts), certUrl)}

    err = SaveCertsPem(derCerts, certFilnam)
    if err != nil {return fmt.Errorf("SaveCerts: %v\n",err)}
	if certobj.Dbg {log.Printf("debug -- saved Cert!")}

	certobj.CertUrl = certUrl
	certobj.CertFilnam = certFilnam

	return nil
}


func (certobj *CertObj) CleanZonesFromDNSChalRecords(crList []CrObj, ctx context.Context) (err error) {

	api := certobj.api

    rc := cloudflare.ResourceContainer{
        Level: cloudflare.ZoneRouteLevel,
//        Identifier: zoneId,
    }

    DnsPar:=cloudflare.ListDNSRecordsParams{
		Type: "TXT",
	}

	for i:=0; i< len(crList); i++ {

		acmeDomain := "_acme-challenge." + crList[i].Zone
		if len(crList[i].ZoneId) == 0 {return fmt.Errorf("Zone[%d] %s has no Id!\n", i+1, crList[i].Zone)}

		rc.Identifier = crList[i].ZoneId
		DnsPar.Name = acmeDomain

		// check cloudflare name servers
		DnsRecList, _, err := api.ListDNSRecords(ctx, &rc, DnsPar)
		if err != nil { return fmt.Errorf("Zone[%d] %s ListDnsRec: %v!\n", i+1, crList[i].Zone, err)}
//		if len(DnsRecList) > 0 {return fmt.Errorf("Zone[%d] %s found challenge record!\n", i+1, crList[i].Zone)}

		// look for dns challenge records
		if len(DnsRecList) > 0 {
			for j:=0; j< len(DnsRecList); j++ {
				recId := DnsRecList[j].ID
				err = api.DeleteDNSRecord(ctx, &rc, recId)
				if err != nil {return fmt.Errorf("DeleteDnsRec: %v", err)}
				if certobj.Dbg {log.Printf("debug -- deleted Dns challenge record in zone: %s\n", crList[i].Zone)}
			}
		}

	}

	return nil
}

func GenCertKey()(certKey *ecdsa.PrivateKey,err error) {

    certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("ecdsa.GenerateKey: %v\n",err)
    }

	return certKey, nil
}


// from https://github.com/eggsampler/acme/blob/master/examples/certbot/certbot.go#L269
func SaveKeyPem(certKey *ecdsa.PrivateKey, keyFilNam string) (err error) {
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding key: %v", err)
	}

	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})

	if err = os.WriteFile(keyFilNam, b, 0600); err != nil {
        return fmt.Errorf("Error writing key file %q: %v", keyFilNam, err)
    }

	return nil
}

func SaveCertsPem(derCerts [][]byte, certFile string)(err error){

	certs := make([]*x509.Certificate, len(derCerts))
	var pemData []string
	for i, asn1Data := range derCerts {
		certs[i], err = x509.ParseCertificate(asn1Data)
		if err != nil {
			return fmt.Errorf("Cert [%d]: %v",i, err)
		}
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[i].Raw,
		}))))

	}

	if err := os.WriteFile(certFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		return fmt.Errorf("Error writing certificate file %q: %v", certFile, err)
	}

	return nil
}

func ReadPemCerts(certFile string, dbg bool)(err error){

	pemData, err := os.ReadFile(certFile)
	if err != nil {return fmt.Errorf("os.ReadFile: %v\n", err)}
	if dbg {fmt.Println("********** start pem file ********")}

	restStart := pemData

	certCount:=0
	for i:=0; i< 10; i++ {
		block, rest := pem.Decode(restStart)
		if block == nil {
			certCount = i
			break
		}
		if dbg {
			fmt.Printf("*** Block[%d] Type: %s ***\n", i+1, block.Type)
			fmt.Printf("  Headers[%d]\n", len(block.Headers))
		}
		for k,v := range block.Headers {
			if dbg {fmt.Printf("  header: %s vlaue %s\n", k, v)}
		}

		derByt := block.Bytes
		cert, err := x509.ParseCertificate(derByt)
		if err != nil {return fmt.Errorf("x509.ParseCertificates: %v", err)}
		PrintCertInfo(*cert, i)

		if dbg {fmt.Printf("*******  End Block ******\n")}

		restStart = rest
	}

	if dbg {
		fmt.Printf("  Certificates: %d\n", certCount)
		fmt.Println("********** end pem file ********")
	}
	return nil
}


func ParseCertsInfo(derCerts [][]byte, certInfoFilnam string)(err error){

	certs := make([]*x509.Certificate, len(derCerts))
	log.Printf("certs: %d\n", len(derCerts))

	for i, asn1Data := range derCerts {
		certs[i], err = x509.ParseCertificate(asn1Data)
		if err != nil {return fmt.Errorf("Cert [%d]: %v",i, err)}
		PrintCertInfo(*certs[i], i)

	}

	return nil
}


/*
// create certficate sign request
func CreateCsrTpl(csrData CsrDat) (template x509.CertificateRequest) {

	nam := csrData.Name
	subj := pkix.Name{
		CommonName:         nam.CommonName,
		Country:            []string{nam.Country},
		Province:           []string{nam.Province},
		Locality:           []string{nam.Locality},
		Organization:       []string{nam.Organisation},
		OrganizationalUnit: []string{"Admin"},
	}

	rawSubj := subj.ToRDNSequence()

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template = x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames: []string{csrData.Domain},
	}
	return template
}

// create certficate sign request
func CreateCsrTplNew(csrList *CsrList, domIdx int) (template x509.CertificateRequest, err error) {

	numAcmeDom := len((*csrList).Domains)
	if numAcmeDom == 0 {return template, fmt.Errorf("no Acme Domains")}
	if domIdx > numAcmeDom-1 {return template, fmt.Errorf("domIdx > numAcmeDom")}

	namIdx :=0
	if domIdx > -1 { namIdx = domIdx }

	nam := (*csrList).Domains[namIdx].Name

fmt.Printf("dbg -- nam[%d;%d]:\n%s\n", domIdx,namIdx, nam.CommonName)

	subj := pkix.Name{
		CommonName:         nam.CommonName,
		Country:            []string{nam.Country},
		Province:           []string{nam.Province},
		Locality:           []string{nam.Locality},
		Organization:       []string{nam.Organisation},
		OrganizationalUnit: []string{"Admin"},
	}

	rawSubj := subj.ToRDNSequence()

	asn1Subj, _ := asn1.Marshal(rawSubj)

	template = x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	dnsNam :=[]string{}

	if domIdx < 0 {
		dnsNam = make([]string, numAcmeDom)
		for i:=0; i<numAcmeDom; i++ {
			dnsNam[i] = (*csrList).Domains[i].Domain
		}
	} else {
		dnsNam = make([]string, 1)
		dnsNam[0] = (*csrList).Domains[domIdx].Domain
	}
	template.DNSNames = dnsNam
	return template, nil
}
*/


func CreateCsr(csrTpl x509.CertificateRequest, certKey *ecdsa.PrivateKey)(csr []byte,err error) {

    csr, err = x509.CreateCertificateRequest(rand.Reader, &csrTpl, certKey)
    if err != nil { return csr, fmt.Errorf("CreateCertReq: %v",err)}

	return csr, nil
}

func ParseCsr(csr []byte) (certReq *x509.CertificateRequest, err error) {

	certReq, err = x509.ParseCertificateRequest(csr)
	if err != nil {return nil, fmt.Errorf("ParseCertificateRequest: %v", err)}

	return certReq, nil
}

func EncodeKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
    x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

    x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

    return string(pemEncoded), string(pemEncodedPub)
}

func DecodeKey(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

    blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    x509EncodedPub := blockPub.Bytes
    genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
    publicKey := genericPublicKey.(*ecdsa.PublicKey)

    return privateKey, publicKey
}

/*
func testKeyEncode() {
    privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    publicKey := &privateKey.PublicKey

    encPriv, encPub := encode(privateKey, publicKey)

    fmt.Println(encPriv)
    fmt.Println(encPub)

    priv2, pub2 := decode(encPriv, encPub)

    if !reflect.DeepEqual(privateKey, priv2) {
        fmt.Println("Private keys do not match.")
    }
    if !reflect.DeepEqual(publicKey, pub2) {
        fmt.Println("Public keys do not match.")
    }
}
*/


// function that saves the keys in certDir
func SaveAcmeClient(client *acme.Client, filNam string) (err error) {

//	privateKey *ecdsa.PrivateKey
	privateKey := (client.Key).(*ecdsa.PrivateKey)

    var publicKey *ecdsa.PublicKey

    publicKey = &privateKey.PublicKey

    privKeyFilNam := filNam + "_priv.key"
    pubKeyFilNam := filNam + "_pub.key"

    x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
    if err != nil {return fmt.Errorf("x509.MarshalECPrivateKey: %v", err)}

    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
    err = os.WriteFile(privKeyFilNam, pemEncoded, 0644)
    if err != nil {return fmt.Errorf("pem priv key write file: %v", err)}

    x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {return fmt.Errorf("x509.MarshalPKIXPublicKey: %v", err)}

    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
    err = os.WriteFile(pubKeyFilNam, pemEncodedPub, 0644)
    if err != nil {return fmt.Errorf("pem pub key write file: %v", err)}

    return nil
}


/*
// function to retrieve keys for LetsEncrypt acme account
func GetAcmeClient(acntFilnam string) (cl *acme.Client, err error) {

    var client acme.Client
	dbg :=false

//	LEDir := os.Getenv("LEDir")
//	if len(LEDir) == 0 {return nil, fmt.Errorf("cannot find LEDir!")}

	if len(acntFilnam) == 0 {
		return nil, fmt.Errorf("no account name provided\n")
	}
	if dbg {log.Printf("info -- account file: %s\n", acntFilnam)}

    acntData, err := os.ReadFile(acntFilnam)
    if err != nil {return nil, fmt.Errorf("cannot read account file! %v", err)}

    leAcnt := LEObj{}

    err = yaml.Unmarshal(acntData, &leAcnt)
    if err != nil {return nil, fmt.Errorf("yaml Unmarshal account file: %v\n", err)}

    if dbg {PrintLEAcnt(&leAcnt)}

    pemEncoded, err := os.ReadFile(leAcnt.PrivKeyFilnam)
    if err != nil {return nil, fmt.Errorf("os.Read Priv Key: %v", err)}

    pemEncodedPub, err := os.ReadFile(leAcnt.PubKeyFilnam)
    if err != nil {return nil, fmt.Errorf("os.Read Pub Key: %v", err)}

    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, err := x509.ParseECPrivateKey(x509Encoded)
    if err != nil {return nil, fmt.Errorf("x509.ParseECPivateKey: %v", err)}

    blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    x509EncodedPub := blockPub.Bytes
    genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
    if err != nil {return nil, fmt.Errorf("x509.ParsePKIXKey: %v", err)}

    publicKey := genericPublicKey.(*ecdsa.PublicKey)
    privateKey.PublicKey = *publicKey

	client.Key = privateKey
	client.DirectoryURL = leAcnt.LEUrl

    return &client, nil
}
*/

// methhod that creates LE client object and verifies LE account
func (certobj *CertObj) GetAcmeClientV2(ctx context.Context) (err error) {

    var client acme.Client
	dbg := certobj.Dbg

//	LEDir := os.Getenv("LEDir")
//	if len(LEDir) == 0 {return nil, fmt.Errorf("cannot find LEDir!")}

	acntFilnam := certobj.AcntFilnam
	if len(acntFilnam) == 0 {
		return fmt.Errorf("no account name provided\n")
	}
	if dbg {log.Printf("info -- account file: %s\n", acntFilnam)}

    acntData, err := os.ReadFile(acntFilnam)
    if err != nil {return fmt.Errorf("cannot read account file! %v", err)}

    leAcnt := LEObj{}

    err = yaml.Unmarshal(acntData, &leAcnt)
    if err != nil {return fmt.Errorf("yaml Unmarshal account file: %v\n", err)}

    if dbg {PrintLEAcnt(&leAcnt)}

    pemEncoded, err := os.ReadFile(leAcnt.PrivKeyFilnam)
    if err != nil {return fmt.Errorf("os.Read Priv Key: %v", err)}

    pemEncodedPub, err := os.ReadFile(leAcnt.PubKeyFilnam)
    if err != nil {return fmt.Errorf("os.Read Pub Key: %v", err)}

    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, err := x509.ParseECPrivateKey(x509Encoded)
    if err != nil {return fmt.Errorf("x509.ParseECPivateKey: %v", err)}

    blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    x509EncodedPub := blockPub.Bytes
    genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
    if err != nil {return fmt.Errorf("x509.ParsePKIXKey: %v", err)}

    publicKey := genericPublicKey.(*ecdsa.PublicKey)
    privateKey.PublicKey = *publicKey

	client.Key = privateKey
	client.DirectoryURL = leAcnt.LEUrl

//	ctx := context.Background()
    acnt, err := client.GetReg(ctx, "")
    if err != nil {return fmt.Errorf("error -- LE GetReg: %v\n", err)}

	certobj.Client = &client
	certobj.LEAccount = acnt
    return nil
}

func (certobj *CertObj) CreateAcmeAccount(acntNam string, ctx context.Context) (err error) {

	dbg := certobj.Dbg

	if len(acntNam) == 0 {
		return fmt.Errorf("no account name provided\n")
	}
	if dbg {log.Printf("info -- account name: %s\n", acntNam)}

	LEDir := certobj.LeDir
    // check for existing keys and yaml file
    acntInfoFilnam := LEDir + "/" + acntNam + "_info.yaml"

    acntData, err := os.ReadFile(acntInfoFilnam)
    if err != nil {return fmt.Errorf("account info: %v", err)}

    acntInfo := AccountInfo{}
    err = yaml.Unmarshal(acntData, &acntInfo)
    if err != nil {return fmt.Errorf("yaml Unmarshal account info: %v\n", err)}

    if dbg {
        fmt.Printf("account info\n")
        fmt.Printf("Name: %s\n", acntInfo.Name)
        fmt.Printf("Contacts:\n")
        for i :=0; i < len(acntInfo.Contacts); i++ {
            fmt.Printf("  %d: %s\n", i+1, acntInfo.Contacts[i])
        }
    }

	fullAcntNam := acntNam
	if certobj.Prod {
		fullAcntNam += "_prod"
	} else {
		fullAcntNam += "_test"
	}
    privFilnam := LEDir + "/" + acntNam + "_priv.key"
    pubFilnam := LEDir + "/" + acntNam + "_pub.key"
    if dbg {
        fmt.Printf("privFilnam: %s\n", privFilnam)
        fmt.Printf("pubFilnam: %s\n", pubFilnam)
    }

/*
type LEObj struct {
	AcntNam string `yaml:"AcntName"`
	AcntId string `yaml:"AcntId"`
	PrivKeyFilnam string `yaml:"PrivKeyFilnam"`
	PubKeyFilnam string `yaml:"PubKeyFilnam"`
	Updated time.Time `yaml:"update"`
	Contacts []string `yaml:"contacts"`
	Type string `yaml:"AcntType:"`
	LEUrl string `yaml:"LEUrl"`
}
*/
	leAcnt := LEObj {
		AcntNam: acntNam,
		PrivKeyFilnam: privFilnam,
		PubKeyFilnam: pubFilnam,
		Contacts: acntInfo.Contacts,
	}

	if certobj.Prod {
		leAcnt.Type = "prod"
		leAcnt.LEUrl = LEProdUrl
	} else {
		leAcnt.Type = "test"
		leAcnt.LEUrl = LETestUrl
	}

    akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { return fmt.Errorf("Generate Key: %v", err)}

    if dbg {log.Printf("newClient: key generated!\n")}

    client := &acme.Client{
        Key: akey,
        DirectoryURL: leAcnt.LEUrl,
        }

	acntTpl:= acme.Account{
        Contact: leAcnt.Contacts,
    }

    acnt, err := client.Register(ctx, &acntTpl, acme.AcceptTOS)
    if err != nil { return fmt.Errorf("client.Register: %v", err)}

    if dbg {
        log.Printf("Directory Url: %s\n", client.DirectoryURL)
        log.Printf("success client and account created!\n")
        PrintClient(client)
        PrintAccount(acnt)
    }

	certobj.Client = client
	certobj.LEAccount = acnt

    privateKey := (client.Key).(*ecdsa.PrivateKey)

    publicKey := &ecdsa.PublicKey{}

    publicKey = &privateKey.PublicKey

    x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
    if err != nil {return fmt.Errorf("x509.MarshalECPrivateKey: %v", err)}

    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

    err = os.WriteFile(privFilnam, pemEncoded, 0644)
    if err != nil {return fmt.Errorf("pem priv key write file: %v", err)}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {return fmt.Errorf("x509.MarshalPKIXPublicKey: %v", err)}

    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
    err = os.WriteFile(pubFilnam, pemEncodedPub, 0644)
    if err != nil {return fmt.Errorf("pem pub key write file: %v", err)}

    leAcnt.Updated = time.Now()
    leAcnt.AcntId = string(client.KID)

    newAcntData, err := yaml.Marshal(&leAcnt)
    if err != nil {return fmt.Errorf("yaml Unmarshal account file: %v\n", err)}

    if err = os.WriteFile(certobj.AcntFilnam, newAcntData, 0600); err != nil {
        return fmt.Errorf("Error writing key file %q: %v", certobj.AcntFilnam, err)
    }

	return nil
}

func (certobj *CertObj) GetAuthOrder(CrList []CrObj, ctx context.Context) (newOrder *acme.Order, err error) {

    numAcmeDom := len(CrList)

    authIdList := make([]acme.AuthzID, numAcmeDom)

    // Authorize all domains provided in the cmd line args.
    for i:=0; i< numAcmeDom; i++ {
        authIdList[i].Type = "dns"
        authIdList[i].Value = CrList[i].Zone
    }

    // lets encrypt does not accept preauthorisation
    // var orderOpt acme.OrderOption
    // OrderOption is contains optional parameters regarding timing

	client := certobj.Client
    order, err := client.AuthorizeOrder(ctx, authIdList)
    if err != nil {return nil, fmt.Errorf("client.AuthorizeOrder: %v\n",err)}

	return order, nil
}

func (certobj *CertObj) GetAuthFromOrder (CrList []CrObj, order *acme.Order, ctx context.Context) (crList []CrObj, err error) {

    numAcmeDom := len(CrList)

	client := certobj.Client

	api := certobj.api

//	log.Printf("cf api: %v\n", api)
    rc := cloudflare.ResourceContainer{
        Level: cloudflare.ZoneRouteLevel,
//        Identifier: param.ZoneID,
    }

    param := cloudflare.CreateDNSRecordParams{
        CreatedOn: time.Now(),
        Type: "TXT",
//        Name: "_acme-challenge",
//        Content: val,
        TTL: 30000,
        Comment: "acme challenge record",
    }

    for i:=0; i< numAcmeDom; i++ {

        url := order.AuthzURLs[i]
		domain :=  CrList[i].Zone
        auth, err := client.GetAuthorization(ctx, url)
        if err != nil {return CrList, fmt.Errorf("client.GetAuthorisation: %v\n",err)}

        if certobj.Dbg {
			log.Printf("debug -- success getting authorization for domain: %s\n", domain)
			PrintAuth(auth)
		}

        // Pick the DNS challenge, if any.
        var chal *acme.Challenge
        for _, c := range auth.Challenges {
            if c.Type == "dns-01" {
                chal = c
                break
            }
        }

		CrList[i].token = chal.Token
		CrList[i].tokURI = chal.URI

        if chal == nil {return CrList, fmt.Errorf("dns-01 challenge is not available for zone %s", domain)}

		if certobj.Dbg {
			log.Printf("debug -- success obtaining challenge\n")
			PrintChallenge(chal, domain)
		}

        // Fulfill the challenge.
        tokVal, err := client.DNS01ChallengeRecord(chal.Token)
        if err != nil {return CrList, fmt.Errorf("dns-01 token for %s: %v", domain, err)}
        if certobj.Dbg {log.Printf("debug -- success obtaining Dns token value: %s\n", tokVal)}

		if certobj.Dbg {log.Printf("debug -- Chal token: %s\n", tokVal)}

		// check that there is no Dns Challenge rexcord
		// if so, delete the record


		// create DNS challenge record
		rc.Identifier = CrList[i].ZoneId

		param.Name = "_acme-challenge." + domain
		param.Content = tokVal

		dnsRec, err := api.CreateDNSRecord(ctx, &rc, param)
		if err != nil {return CrList, fmt.Errorf("CreateDnsREc: %v", err)}

		if certobj.Dbg {log.Printf("debug -- DnsRec: %v\n", dnsRec)}
	}
	return CrList, nil
}

func CheckDnsProbagation(CrList []CrObj) (err error) {

    numAcmeDom := len(CrList)

    for i:=0; i< numAcmeDom; i++ {
		tgtZone := CrList[i].Zone
		acmeDomain := "_acme-challenge." + tgtZone
//		txtRecs, err := net.LookupTXT(acmeDomain)
		_, err := net.LookupTXT(acmeDomain)
		if err != nil {
			errStr := err.Error()
//			log.Printf("*** errStr: %s\n", errStr)
			if idx := strings.Index(errStr, "127.0.0.53:53"); idx>1 {
				return fmt.Errorf("domain %s acme dns rec not yet found!")
			} else {
				return fmt.Errorf("domain %s lookup error: %v", err)
			}
		}
	}

	return nil
}

func PrintLEAcnt(acnt *LEObj) {

	fmt.Printf("*************** LEAcnt *******************\n")
	fmt.Printf("Acnt Name:  %s\n", acnt.AcntNam)
	fmt.Printf("AcntId:     %s\n", acnt.AcntId)
	fmt.Printf("update:     %s\n", acnt.Updated.Format(time.RFC1123))
	fmt.Printf("LE Url:     %s\n", acnt.LEUrl)
	fmt.Printf("type:       %s\n", acnt.Type)
	fmt.Printf("contacts:   %d\n", len(acnt.Contacts))
	for i:=0; i< len(acnt.Contacts); i++ {
		fmt.Printf("contact[%d]: %s\n", i+1, acnt.Contacts[i])
	}
	fmt.Printf("Public Key File:  %s\n", acnt.PubKeyFilnam)
	fmt.Printf("Private Key File: %s\n", acnt.PrivKeyFilnam)
	fmt.Printf("*************** End LEAcnt ****************\n")
}


func PrintAccount (acnt *acme.Account) {

    fmt.Println("***************** Acme Account ******************")
    fmt.Printf("URI:    %s\n", acnt.URI)
    fmt.Printf("Status: %s\n", acnt.Status)
    fmt.Printf("Contacts [%d]:\n", len((*acnt).Contact))
    for i:=0; i< len((*acnt).Contact); i++ {
        fmt.Printf("Contact[%d]: %s\n", i, (*acnt).Contact[i])
    }
    fmt.Printf("OrdersURL:   %s\n", acnt.OrdersURL)
    fmt.Println (" *** non RFC 8588 terms:  ***")
    fmt.Printf("  AgreedTerms: %s\n", acnt.AgreedTerms)
    fmt.Printf("  Authz: %s\n", acnt.Authz)
    fmt.Println("***************** End Acme Account ******************")
}

func PrintJsAccount (acnt *JsAcnt) {

    fmt.Println("***************** Acme JsAccount ******************")
    fmt.Printf("URI:  %s\n", acnt.URI)
    fmt.Printf("Contacts [%d]:\n", len((*acnt).Contact))
    for i:=0; i< len((*acnt).Contact); i++ {
        fmt.Printf("Contact[%d]: %s\n", i, (*acnt).Contact[i])
    }
    fmt.Printf("OrdersURL:   %s\n", acnt.OrdersURL)
    fmt.Printf("AgreedTerms: %s\n", acnt.AgreedTerms)
}

func PrintClient (client *acme.Client) {

    fmt.Println("************** Acme Client ******************")
	if client.Key != nil {
    	fmt.Printf("Key exists\n")
	} else {
		fmt.Printf("no Key found!\n")
	}
    fmt.Printf("HTTPClient: %v\n",client.HTTPClient)
    fmt.Printf("Directory: %s\n", client.DirectoryURL)
    fmt.Printf("Retry: %v\n", client.RetryBackoff)
    fmt.Printf("UserAgent: %s\n",client.UserAgent)
    fmt.Printf("KID: %s\n", client.KID)
    fmt.Println("***************** End Client ******************")
}

func PrintAuth(auth *acme.Authorization) {
    fmt.Println("************************* authorization *********************")
    fmt.Printf("URI:    %s\n", auth.URI)
    fmt.Printf("Status: %s\n", auth.Status)
    fmt.Printf("Id typ: %s val: %s\n", auth.Identifier.Type, auth.Identifier.Value)
    ExpTimStr:= auth.Expires.Format(time.RFC1123)
    fmt.Printf("Expires %s\n", ExpTimStr)
    fmt.Printf("*** Challenges[%d] ***\n", len(auth.Challenges))
    for i, chal := range auth.Challenges {
        fmt.Printf("   [%d]: %s URI: %s Token: %s Status: %s err: %v\n", i+1, chal.Type, chal.URI, chal.Token, chal.Status, chal.Error)
	}
    fmt.Println("********************** end authorization ********************")
}

func PrintChallenge(chal *acme.Challenge, domain string) {
    fmt.Printf("*************** Challenge for domain: %s *******\n", domain)
    fmt.Printf("Type:     %s\n", chal.Type)
    fmt.Printf("URI:      %s\n", chal.URI)
    fmt.Printf("Token:    %s\n", chal.Token)
    fmt.Printf("Status:   %s\n", chal.Status)
	if chal.Validated.IsZero() {
    	fmt.Printf("Validate: NA\n")
	} else {
    	fmt.Printf("Validate: %s\n", chal.Validated.Format(time.RFC1123))
	}
    fmt.Printf("Error:    %v\n", chal.Error)
    fmt.Printf("*************** End Challenge *****************\n")
}

func PrintDomains(domains []string) {
    fmt.Printf("*****  domains: %d *******\n", len(domains))
    for i, domain := range domains {
        fmt.Printf("domain[%d]: %s\n", i+1, domain)
    }
    fmt.Printf("***** end domains *******\n")
}

func PrintDir(dir acme.Directory) {

    fmt.Println("************************* Directory **********************")
    fmt.Printf("AuthzUrl: %s\n", dir.AuthzURL)
    fmt.Printf("OrderUrl: %s\n", dir.OrderURL)
    fmt.Printf("RevokeUrl: %s\n", dir.RevokeURL)
    fmt.Printf("NonceUrl: %s\n", dir.NonceURL)
    fmt.Printf("KeyChangeUrl: %s\n", dir.KeyChangeURL)
    fmt.Printf("Meta Terms: %v\n",  dir.Terms)
    fmt.Printf("Meta Website: %s\n", dir.Website)
    fmt.Printf("Meta CAA: %s\n", dir.CAA)
    fmt.Printf("External Account Req: %v\n", dir.ExternalAccountRequired)
    fmt.Println("********************** End Directory *********************")
}

func PrintOrder(ord *acme.Order) {
	if ord == nil {fmt.Println("cannot print -- order pointer is nil!\n")}

    fmt.Println("*********************** Order ****************************")
    fmt.Printf("URI: %s\n", ord.URI)
    fmt.Printf("Status: %s\n", ord.Status)
    fmt.Printf("Expires: %s\n", ord.Expires.Format(time.RFC1123))
    fmt.Printf("Identifiers: %d\n", len(ord.Identifiers))
    for i:= 0; i< len(ord.Identifiers); i++ {
        id := ord.Identifiers[i]
        fmt.Printf("  id[%d]: typ: %s val %s\n", i+1, id.Type, id.Value)
    }
    fmt.Printf("Authorisation URLs: %d\n", len(ord.AuthzURLs))
    for i:= 0; i< len(ord.AuthzURLs); i++ {
        id := ord.AuthzURLs[i]
        fmt.Printf("  auth for id[%d]: %s\n", i+1, id)
    }
    fmt.Printf("FinalizeURL: %s\n", ord.FinalizeURL)
    fmt.Printf("CertURL: %s\n", ord.CertURL)
    fmt.Printf("error: %v\n", ord.Error)
    fmt.Println("******************* End Order ****************************")
}

func PrintCertInfo(cert x509.Certificate, i int){

/*
	sigAlgo := []string {
		"Unknown",
		"MD2WithRSA",  // Unsupported.
		"MD5WithRSA",  // Only supported for signing, not verification.
		"SHA1WithRSA", // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
		"SHA256WithRSA",
		"SHA384WithRSA",
		"SHA512WithRSA",
		"DSAWithSHA1",   // Unsupported.
		"DSAWithSHA256", // Unsupported.
		"ECDSAWithSHA1", // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
		"ECDSAWithSHA256",
		"ECDSAWithSHA384",
		"ECDSAWithSHA512",
		"SHA256WithRSAPSS",
		"SHA384WithRSAPSS",
		"SHA512WithRSAPSS",
		"PureEd25519",
	}

	pubKeyAlgo := []string{
		"Unknown",
		"RSA",
		"DSA", // Only supported for parsing.
		"ECDSA",
		"Ed25519",
	}
*/
	fmt.Printf("******** Cert %d ********\n", i+1)
	fmt.Printf("version: %d\n", cert.Version)
	fmt.Printf("SerialNum: %s\n", (*cert.SerialNumber).String())

	fmt.Printf("Signature Algo:    %s\n", cert.SignatureAlgorithm.String())
	fmt.Printf("Public Key Algo: %s\n", cert.PublicKeyAlgorithm.String())
//	fmt.Printf("Signature Algo[%d]: %s\n", cert.SignatureAlgorithm, sigAlgo[cert.SignatureAlgorithm])
//	fmt.Printf("Public Key Algo[%d]: %s\n", cert.PublicKeyAlgorithm, pubKeyAlgo[cert.PublicKeyAlgorithm])

	fmt.Printf("Not Before: %s\n", cert.NotBefore.Format(time.RFC1123))
	fmt.Printf("Not After:  %s\n", cert.NotAfter.Format(time.RFC1123))


	fmt.Printf("Issuer IsCA: %t\n", cert.IsCA)
//	fmt.Printf("\nIssuer: \n")
	PrintPkixNam(cert.Issuer)

	fmt.Printf("\nSubject: \n")
	PrintPkixNam(cert.Subject)

	fmt.Printf("DNS Names  [%d]:\n", len(cert.DNSNames))
	if len(cert.DNSNames) > 0 {
		for k:=0; k< len(cert.DNSNames); k++ {
			fmt.Printf("  %d: %s\n", k+1, cert.DNSNames[k])
		}
	}
	fmt.Printf("Email Adrs [%d]:\n", len(cert.EmailAddresses))
	fmt.Printf("IP Adrs [%d]:\n", len(cert.IPAddresses))
	if len(cert.IPAddresses) > 0 {
		for k:=0; k< len(cert.IPAddresses); k++ {
			fmt.Printf("  %d: %s\n", k+1, cert.IPAddresses[k])
		}
	}
	fmt.Printf("URIs [%d]:\n", len(cert.URIs))
	if len(cert.URIs) > 0 {
		for k:=0; k< len(cert.URIs); k++ {
			fmt.Printf("  %d: %s\n", k+1, *cert.URIs[k])
		}
	}

	fmt.Printf("Name Constraints:\n")
	fmt.Printf("  PermittedDNSDomains [%d]:\n", len(cert.PermittedDNSDomains))
	if len(cert.PermittedDNSDomains) > 0 {
		for k:=0; k< len(cert.PermittedDNSDomains); k++ {
			fmt.Printf("    %d: %s\n", k+1, cert.PermittedDNSDomains[k])
		}
	}
	fmt.Printf("  ExcludedDNSDomains [%d]:\n", len(cert.ExcludedDNSDomains))
	if len(cert.ExcludedDNSDomains) > 0 {
		for k:=0; k< len(cert.ExcludedDNSDomains); k++ {
			fmt.Printf("    %d: %s\n", k+1, cert.ExcludedDNSDomains[k])
		}
	}

//	fmt.Printf("Extensions[%d]:\n", len(cert.Extensions))
	switch len(cert.Extensions) {
	case 0:
		fmt.Printf("Extensions: ---\n")
	case 1:
		ext := cert.Extensions[0]
		fmt.Printf("Extension: Id %d Value: %v Critical: %t\n", ext.Id, ext.Value, ext.Critical)
	default:
		fmt.Printf("Extensions: %d\n", len(cert.Extensions))
		for k:=0; k< len(cert.Extensions); k++ {
			ext := cert.Extensions[k]
			fmt.Printf("  %d: Id %d Value: %v Critical: %t\n", k+1, ext.Id, ext.Value, ext.Critical)
		}
	}
	fmt.Printf("Extra Extensions[%d]:\n", len(cert.ExtraExtensions))
	fmt.Printf("Unhandled Crtical Extensions[%d]:\n", len(cert.UnhandledCriticalExtensions))

	if len(cert.OCSPServer) == 0 {
		fmt.Printf("OCSPServer: ---\n")
	} else {
		fmt.Printf("OCSPServer [%d]: \n",len(cert.OCSPServer))
		for i:=0; i<len(cert.OCSPServer); i++ {
			fmt.Printf("  %d: %s\n", i+1, cert.OCSPServer[i])
		}
	}
	if len(cert.IssuingCertificateURL) == 0 {
		fmt.Printf("Issuing Certificate URLs: ---\n")
	} else {
		fmt.Printf("Issuing Certificate URLs [%d]: \n", len(cert.IssuingCertificateURL))
		for i:=0; i< len(cert.IssuingCertificateURL); i++ {
			fmt.Printf("  %d: %s\n", i+1, cert.IssuingCertificateURL[i])
		}
	}
	fmt.Printf("******* End Cert ********\n")
}

func PrintCert(cert *x509.Certificate) {

	fmt.Println("************ Certificate **************")

	fmt.Printf("Version: %d\n", cert.Version)
	fmt.Printf("Serial:  %s\n", (*cert.SerialNumber).String())
	fmt.Printf("Sig Algo:    %s\n", cert.SignatureAlgorithm.String())
	fmt.Printf("PubKey Algo: %s\n", cert.PublicKeyAlgorithm.String())

	fmt.Printf("Issuer: %t\n", cert.IsCA)
	PrintPkixNam(cert.Issuer)

	fmt.Printf("Subject: \n")
	PrintPkixNam(cert.Subject)

	fmt.Printf("Start: %s\n", cert.NotBefore.Format(time.RFC1123))
	fmt.Printf("End:   %s\n", cert.NotAfter.Format(time.RFC1123))

	fmt.Printf("DNS Names: %d\n", len(cert.DNSNames))
	for i:=0; i< len(cert.DNSNames); i++ {
		fmt.Printf("    %d:%s\n", i+1, cert.DNSNames[i])
	}
	fmt.Printf("IP Adrs: %d\n", len(cert.IPAddresses))
	for i:=0; i< len(cert.IPAddresses); i++ {
		fmt.Printf("    %d:%s\n", i+1, cert.IPAddresses[i])
	}

	fmt.Printf("Extensions[%d]:\n", len(cert.Extensions))
	fmt.Printf("Extra Extensions[%d]:\n", len(cert.ExtraExtensions))
	fmt.Printf("Unhandled Crtical Extensions[%d]:\n", len(cert.UnhandledCriticalExtensions))

	fmt.Printf("OCSPServer [%d]: \n", len(cert.OCSPServer))
	fmt.Printf("Issuing Certificate URLs [%d]: \n", len(cert.IssuingCertificateURL))

	fmt.Println("********** End Certificate ************")

}

func PrintPkixNam(subj pkix.Name) {
	if len(subj.SerialNumber) == 0 {
		fmt.Printf("  Serial Number: ---\n")
	} else {
		fmt.Printf("  Serial Number: %s\n", subj.SerialNumber)
	}

	if len(subj.CommonName) ==0 {
		fmt.Printf("  CommonName: ---\n")
	} else {
		fmt.Printf("  CommonName: %s\n", subj.CommonName)
	}

	switch len(subj.Country) {
	case 0:
    	fmt.Printf("  Country: --\n")
	case 1: 
    	fmt.Printf("  Country: %s\n", subj.Country[0])
	default:
	    fmt.Printf("  Countries[%d]:\n", len(subj.Country))
	    for i:=0; i< len(subj.Country); i++ {
    	    fmt.Printf("%d: %s\n", i+1, subj.Country[i])
    	}
	}

	switch len(subj.Organization) {
	case 0:
		fmt.Printf("  Organization: ---\n")
	case 1:
		fmt.Printf("  Organization: %s\n",subj.Organization[0])
	default:
		fmt.Printf("  Organizations[%d]:\n", len(subj.Organization))
    	for i:=0; i< len(subj.Organization); i++ {
        	fmt.Printf("%d: %s\n", i+1, subj.Organization[i])
    	}
	}

	switch len(subj.OrganizationalUnit) {
	case 0:
		fmt.Printf("  Organizational Unit: ---\n")
	case 1:
		fmt.Printf("  Organizational Unit: %s\n",subj.OrganizationalUnit[0])
	default:
		fmt.Printf("  Organizational Units[%d]:\n", len(subj.OrganizationalUnit))
    	for i:=0; i< len(subj.OrganizationalUnit); i++ {
        	fmt.Printf("%d: %s\n", i+1, subj.OrganizationalUnit[i])
    	}
	}

	switch len(subj.Locality) {
	case 0:
	    fmt.Printf("  Locality: ---\n")
	case 1:
	    fmt.Printf("  Locality: %s\n", subj.Locality[0])
	default:
    	fmt.Printf("  Localities[%d]:\n", len(subj.Locality))
    	for i:=0; i< len(subj.Locality); i++ {
        	fmt.Printf("%d: %s\n", i+1, subj.Locality[i])
    	}
	}

	switch len(subj.Province) {
	case 0:
	    fmt.Printf("  Province: ---\n")
	case 1:
	    fmt.Printf("  Province: %s\n", subj.Province[0])
	default:
    	fmt.Printf("  Provinces[%d]:\n", len(subj.Province))
    	for i:=0; i< len(subj.Province); i++ {
        	fmt.Printf("%d: %s\n", i+1, subj.Province[i])
    	}
	}

	switch len(subj.StreetAddress) {
	case 0:
	    fmt.Printf("  StreetAddress: ---\n")
	case 1:
	    fmt.Printf("  StreetAddress: %s\n", subj.StreetAddress[0])
	default:
    	fmt.Printf("  StreetAddresses[%d]:\n", len(subj.StreetAddress))
    	for i:=0; i< len(subj.StreetAddress); i++ {
        	fmt.Printf("%d: %s\n", i+1, subj.StreetAddress[i])
    	}
	}

	switch len(subj.PostalCode) {
	case 0:
	    fmt.Printf("  PostalCode: ---\n")
	case 1:
	    fmt.Printf("  PostalCode: %s\n", subj.PostalCode[0])
	default:
    	fmt.Printf("  PostalCodes[%d]\n", len(subj.PostalCode))
    	for i:=0; i< len(subj.PostalCode); i++ {
        	fmt.Printf("%d: %s\n", i+1, subj.PostalCode[i])
    	}
	}

	if len(subj.Names) == 0 {
	    fmt.Printf("  Names: ---\n")
	} else {
	    fmt.Printf("  Names[%d]:\n", len(subj.Names))
    	for i:=0; i< len(subj.Names); i++ {
        	fmt.Printf("%d: %v\n", i+1, subj.Names[i])
    	}
	}

	if len(subj.ExtraNames) == 0 {
		fmt.Printf("  ExtraNames: ---\n")
	} else {
	    fmt.Printf("  ExtraNames{%d]:\n", len(subj.ExtraNames))
    	for i:=0; i< len(subj.ExtraNames); i++ {
        	fmt.Printf("%d: %v\n", i+1, subj.ExtraNames[i])
		}
    }
}

func PrintCsr(req *x509.CertificateRequest) {

	fmt.Println("******************* CSR ********************")
	fmt.Printf("DNS Names %d\n", len(req.DNSNames))
	for i:=0; i< len(req.DNSNames); i++ {
		fmt.Printf("%d: %s\n", i+1, req.DNSNames[i])
	}
	fmt.Printf("URIs      %d\n", len(req.URIs))
	for i:=0; i< len(req.URIs); i++ {
		uri := *req.URIs[i]
		fmt.Printf("%d: %v\n", i+1, uri)
	}
	fmt.Printf("Version: %d\n", req.Version)
	fmt.Printf("Subject:\n")

	subj := req.Subject
	fmt.Printf("  Serial Number: %s\n", subj.SerialNumber)
	fmt.Printf("  CommonName: %s\n", subj.CommonName)
	fmt.Printf("  Country %d\n", len(subj.Country))
	for i:=0; i< len(subj.Country); i++ {
		fmt.Printf("%d: %s\n", i+1, subj.Country[i])
	}
	fmt.Printf("  Locality %d\n", len(subj.Locality))
	for i:=0; i< len(subj.Locality); i++ {
		fmt.Printf("%d: %s\n", i+1, subj.Locality[i])
	}
	fmt.Printf("  Names %d\n", len(subj.Names))
	for i:=0; i< len(subj.Names); i++ {
		fmt.Printf("%d: %v\n", i+1, subj.Names[i])
	}
	fmt.Printf("  ExtraNames %d\n", len(subj.ExtraNames))
	for i:=0; i< len(subj.ExtraNames); i++ {
	    fmt.Printf("Subject:\n")
		fmt.Printf("%d: %v\n", i+1, subj.ExtraNames[i])
	}
    fmt.Printf("Extensions: %d\n", len(req.Extensions))
    for i:=0; i< len(req.Extensions); i++ {
		ext := req.Extensions[i]
        fmt.Printf("%d: %v %t %s %d\n", i+1, ext.Id, ext.Critical, string(ext.Value), len(ext.Value))
    }
    fmt.Printf("ExtraExtensions: %d\n", len(req.ExtraExtensions))
    for i:=0; i< len(req.ExtraExtensions); i++ {
		ext := req.ExtraExtensions[i]
        fmt.Printf("%d: %v\n", i+1, ext)
    }

	fmt.Println("****************** End CSR ******************")
}


func PrintCertObj(cert *CertObj) {

	fmt.Printf("**************** certLibObj *****************\n")
	fmt.Printf("Account File: %s\n", cert.AcntFilnam)
	fmt.Printf("ZoneDir:      %s\n", cert.ZoneDir)
	fmt.Printf("CertDir:      %s\n", cert.CertDir)
	fmt.Printf("LE Dir:       %s\n", cert.LeDir)
	fmt.Printf("CF Dir:       %s\n", cert.CfDir)
	fmt.Printf("Csr Dir:      %s\n", cert.CsrDir)
	fmt.Printf("Cf Token:     %s\n", cert.CfToken)
	fmt.Printf("Production:   %t\n", cert.Prod)
	fmt.Printf("debug:        %t\n", cert.Dbg)
	fmt.Printf("************** end certLibObj ***************\n")
}

func PrintCrList(CrList []CrObj) {

    fmt.Printf("************** Cr List %d ****************\n", len(CrList))

	for i:=0; i< len(CrList); i++ {
		Cr := CrList[i]
    	fmt.Printf("************** Cr %d ****************\n", i+1)
		fmt.Printf("Zone:         %s\n", Cr.Zone)
    	fmt.Printf("Zone Id:      %s\n", Cr.ZoneId)
    	fmt.Printf("Email:        %s\n", Cr.Email)
    	fmt.Printf("Start:        %s\n", Cr.Start.Format(time.RFC1123))
    	fmt.Printf("Country:      %s\n", Cr.Country)
    	fmt.Printf("Province:     %s\n", Cr.Province)
    	fmt.Printf("Locality:     %s\n", Cr.Locality)
    	fmt.Printf("Organisation: %s\n", Cr.Organisation)
    	fmt.Printf("OrganisationUnit: %s\n", Cr.OrganisationUnit)
	}
    fmt.Printf("************** End Cr List ****************\n")

}

func PrintZones(zones []cloudflare.Zone) {

    fmt.Printf("************** Zones/Domains [%d] ***************\n", len(zones))

    for i:=0; i< len(zones); i++ {
        zone := zones[i]
        fmt.Printf("%d %-20s %s\n",i+1, zone.Name, zone.ID)
    }
    fmt.Printf("************** End Zones/Domains *****************\n", len(zones))


}

func (c *CertObj) PrintCertObj() {

	fmt.Println("*************** CertObj *****************")
	fmt.Printf("ZoneDir: %s\n", c.ZoneDir)
	fmt.Printf("CertDir: %s\n", c.CertDir)
	fmt.Printf("CertName: %s\n", c.CertName)
	fmt.Printf("ZoneFilnam: %s\n", c.ZoneFilnam)
	fmt.Printf("AcntFilnam: %s\n", c.AcntFilnam)
	fmt.Printf("FinalUrl: %s\n", c.FinalUrl)
	fmt.Printf("CertUrl:  %s\n", c.CertUrl)
	fmt.Printf("LE Dir: %s\n", c.LeDir)
	fmt.Printf("Cf Dir: %s\n", c.CfDir)
	fmt.Printf("Csr Dir: %s\n", c.CsrDir)
	fmt.Printf("Dbg: %t\n", c.Dbg)
	fmt.Printf("Prod: %t\n", c.Prod)
	if c.Client == nil {
		fmt.Printf("no Client!\n")
	} else {
		fmt.Printf("has Client!\n")
	}

	if c.api == nil {
		fmt.Printf("no Cf api!\n")
	} else {
		fmt.Printf("has Cf api!\n")
	}

	if c.LEAccount == nil {
		fmt.Printf("no LE acme account!\n")
	} else {
		fmt.Printf("has LE acme account!\n")
	}

	fmt.Println("************* End CertObj ***************")
}

