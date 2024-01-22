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
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"

   "golang.org/x/crypto/acme"

    yaml "github.com/goccy/go-yaml"
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
//	Remove bool `yaml:"remove"`
	Type string `yaml:"type:"`
//	TestUrl string `yaml:"TestUrl"`
	LEUrl string `yaml:"ProdUrl"`
}

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

type CertList struct {
	CertNam string `yaml:"certName"`
	Domains []string `yaml:"domains"`
	LEUrl string	`yaml:"LEUrl"`
	Valid	time.Time	`yaml:"valid"`
	Expire time.Time	`yaml:"expire"`
}


type pkixName struct {
    CommonName string `yaml:"CommonName"`
    Country string `yaml:"Country"`
    Province string `yaml:"Province"`
    Locality string `yaml:"Locality"`
    Organisation string `yaml:"Organisation"`
    OrganisationUnit string `yaml:"OrganisationUnit"`
}

type certLibObj struct {
	ZoneDir string
	CertDir string
	LeDir string
	CfDir string
	CsrDir string
	CfApiFilnam string
	ZoneFilnam string
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


func InitCertLib()(certobj *certLibObj, err error) {

	certObj:=certLibObj {}
    zoneDir := os.Getenv("zoneDir")
    if len(zoneDir) == 0 {return nil, fmt.Errorf("could not resolve env var zoneDir!")}
	certObj.ZoneDir = zoneDir
	certObj.ZoneFilnam = zoneDir + "/cfDomainsShort.yaml"

    leAcnt := os.Getenv("LEAcnt")
    if len(leAcnt) < 1 {return nil, fmt.Errorf("could not resolve env var LEAcnt!")}
	certObj.LeDir = leAcnt + "/account"
//    csrFilnam := leAcnt + "csrList/csrTest.yaml"
	certObj.CertDir = leAcnt + "/certs"

    cfDir := os.Getenv("Cloudflare")
    if len(cfDir) == 0 {return nil, fmt.Errorf("could not resolve env var cfDir!")}
	certObj.CfDir = cfDir
//    certObj.CfApiFilnam = cfDir + "/token/cfDns.yaml"
    certObj.CfApiFilnam = "cfDns.yaml"

	certObj.CsrDir = leAcnt+ "/csrList/"

	return &certObj, nil
}


/*
func GetCertDir(acntNam string)(certDir string, err error) {

    leAcnt := os.Getenv("LEAcnt")
    if len(leAcnt) < 1 {return "", fmt.Errorf("could not resolve env var LEAcnt!")}
	certDir = leAcnt + "/account"

    // This returns an *os.FileInfo type
    fileInfo, err := os.Stat(certDir)
    if err != nil {
		return "", fmt.Errorf("dir %s not found: %v\n", certDir, err)
    }

    // IsDir is short for fileInfo.Mode().IsDir()
    if !fileInfo.IsDir() {
		return "", fmt.Errorf("%s not a directory!\n", certDir)
    }

	byt := []byte(certDir)
	if byt[len(byt)-1] != '/' {certDir += "/"}

	return certDir, nil
}
*/
func GenCertKey()(certKey *ecdsa.PrivateKey,err error) {

    certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("ecdsa.GenerateKey: %v\n",err)
    }

	return certKey, nil
}


// functions that reads CSRList from a file
func ReadCsrFil(inFilnam string)(csrDatList *CsrList, err error) {

    //todo check for yaml extension
	idx := strings.Index(inFilnam,".yaml")
	if idx == -1 {inFilnam += ".yaml"}

    bytData, err := os.ReadFile(inFilnam)
    if err != nil {
        return nil, fmt.Errorf("os.ReadFile: %v\n",err)
    }

    csrList := &CsrList{}
    err = yaml.Unmarshal(bytData, csrList)
    if err != nil {
        return nil, fmt.Errorf("yaml Unmarshal: %v\n", err)
    }

    return csrList, nil
}

func WriteCsrFil(outFilnam string, csrDatList *CsrList) (err error) {

    csrByte, err := yaml.Marshal(csrDatList)
	if err!= nil {
		return fmt.Errorf("Marshal: %v\n",err)
	}

	idx := strings.Index(outFilnam, ".yaml")
	if idx == -1 {outFilnam += ".yaml"}

	outfil, err := os.Create(outFilnam)
	if err!= nil {return fmt.Errorf("CreateFile: %v\n",err)}

//	err = os.WriteFile(outFilnam, csrByte, 0666)
	_, err = outfil.Write(csrByte)
	if err!= nil {return fmt.Errorf("WriteFile: %v\n",err)}
	return nil
}

// function that creates a new client
func CreateLEAccount(acntFilInfo string, prod bool) (err error) {

	dbg := true

	// find LE folder
	LEDir := os.Getenv("LEDir")
	if len(LEDir) == 0 {return fmt.Errorf("LEDir not found!")}

	acntFilInfoNam := LEDir + "/" + acntFilInfo + ".yaml"
	acntData, err := os.ReadFile(acntFilInfoNam)
	if err != nil {return fmt.Errorf("Read acntinfo: %v!", err)}

//	fmt.Printf("acntData: %s\n", acntData)
    acntInfo := AccountInfo{}
    err = yaml.Unmarshal(acntData, &acntInfo)
    if err != nil {return fmt.Errorf("yaml Unmarshal account file: %v\n", err)}

    if dbg {
        fmt.Printf("account info\n")
        fmt.Printf("Name: %s\n", acntInfo.Name)
        fmt.Printf("Contacts:\n")
        for i :=0; i < len(acntInfo.Contacts); i++ {
            fmt.Printf("  %d: %s\n", i+1, acntInfo.Contacts[i])
        }
    }

	// check for existing keys and yaml file
	acntNam := acntInfo.Name
	acntFilnam := ""
	privKeyFilnam :=""
	pubKeyFilnam := ""
	if prod {
		acntFilnam = LEDir + "/" + acntNam +"_prod.yaml"
		privKeyFilnam = LEDir + "/" + acntNam + "_prodPriv.key"
		pubKeyFilnam = LEDir + "/" + acntNam + "_prodPub.key"
	} else {
		acntFilnam = LEDir + "/" + acntNam +"_test.yaml"
		privKeyFilnam = LEDir + "/" + acntNam + "_testPriv.key"
		pubKeyFilnam = LEDir + "/" + acntNam + "_testPub.key"
	}

	if dbg {
		fmt.Printf("acntFilnam: %s\n", acntFilnam)
		fmt.Printf("privFilnam: %s\n", privKeyFilnam)
		fmt.Printf("pubFilnam: %s\n", pubKeyFilnam)
	}

	// instantiate and populate LEObj
	leAcnt := LEObj{}

	if prod {
		leAcnt.Type = "prod"
		leAcnt.LEUrl = LEProdUrl
	} else {
		leAcnt.Type = "test"
		leAcnt.LEUrl = LETestUrl
	}

	leAcnt.PrivKeyFilnam = privKeyFilnam
	leAcnt.PubKeyFilnam = pubKeyFilnam
	leAcnt.AcntNam = acntInfo.Name
	leAcnt.Contacts = acntInfo.Contacts

	if dbg {PrintLEAcnt(&leAcnt)}

    akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { return fmt.Errorf("Generate Key: %v", err)}

    if dbg {log.Printf("newClient: key generated!\n")}

    client := &acme.Client{
		Key: akey,
		DirectoryURL: leAcnt.LEUrl,
		}


    if dbg {
        log.Printf("Directory Url: %s\n", client.DirectoryURL)
        log.Printf("success client created!\n")
        PrintClient(client)
    }

	acntTpl:= acme.Account{
		Contact: leAcnt.Contacts,
	}

	ctx := context.Background()

    acnt, err := client.Register(ctx, &acntTpl, acme.AcceptTOS)
    if err != nil { return fmt.Errorf("client.Register: %v", err)}

	log.Printf("success CA account generated\n")

    if dbg {
		PrintClient(client)
		PrintAccount(acnt)
	}

	privateKey := (client.Key).(*ecdsa.PrivateKey)

    publicKey := &ecdsa.PublicKey{}

    publicKey = &privateKey.PublicKey

    x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
    if err != nil {return fmt.Errorf("x509.MarshalECPrivateKey: %v", err)}

    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

    err = os.WriteFile(privKeyFilnam, pemEncoded, 0644)
    if err != nil {return fmt.Errorf("pem priv key write file: %v", err)}

    x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {return fmt.Errorf("x509.MarshalPKIXPublicKey: %v", err)}

    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
    err = os.WriteFile(pubKeyFilnam, pemEncodedPub, 0644)
    if err != nil {return fmt.Errorf("pem pub key write file: %v", err)}

	leAcnt.Updated = time.Now()
	leAcnt.AcntId = string(client.KID)

    newAcntData, err := yaml.Marshal(&leAcnt)
    if err != nil {return fmt.Errorf("yaml Unmarshal account file: %v\n", err)}

	if err = os.WriteFile(acntFilnam, newAcntData, 0600); err != nil {
        return fmt.Errorf("Error writing key file %q: %v", acntFilnam, err)
    }

	log.Printf("wrote new LE Account file\n")

    return nil
}


func GetLEClient(acntNam string, dbg bool) (cl *acme.Client, err error) {

	client :=acme.Client{}

	LEDir := os.Getenv("LEDir")
	if len(LEDir) == 0 {return nil, fmt.Errorf("cannot find LEDir!")}

	acntFilnam := LEDir + "LEAcnt.yaml"
	if len(acntNam) > 0 {
		acntFilnam = LEDir + acntNam + ".yaml"
		log.Printf("account file: %s\n", acntFilnam)
	} else {
		log.Printf("no account file provided using default!")
	}

	acntData, err := os.ReadFile(acntFilnam)
	if err != nil {return nil, fmt.Errorf("account ReadFile: %v", err)}

	leAcnt := LEObj{}

    err = yaml.Unmarshal(acntData, &leAcnt)
    if err != nil {return nil, fmt.Errorf("yaml Unmarshal account file: %v\n", err)}
	if dbg {PrintLEAcnt(&leAcnt)}

	if len(leAcnt.AcntId) == 0 {
		return nil, fmt.Errorf("no CA acount id found!\n")
	}

	if len(leAcnt.PrivKeyFilnam) == 0 {
		return nil, fmt.Errorf("no private Key file name found!\n")
	}
	if len(leAcnt.PubKeyFilnam) == 0 {
		return nil, fmt.Errorf("no public Key file name found!\n")
	}

	privFilnam := leAcnt.PrivKeyFilnam
	pubFilnam := leAcnt.PubKeyFilnam

	_, err = os.Stat(privFilnam)
	if err != nil {
		return nil, fmt.Errorf("no private key file: %v", err)
	}

	_, err = os.Stat(pubFilnam)
	if err != nil {
		return nil, fmt.Errorf("no public key file: %v", err)
	}

	client.DirectoryURL = leAcnt.LEUrl

	if dbg {fmt.Printf("Acme Url [prod: %t]: %s\n", leAcnt.Type, client.DirectoryURL)}

    pemEncoded, err := os.ReadFile(privFilnam)
    if err != nil {return nil, fmt.Errorf("os.Read Priv Key: %v", err)}

    pemEncodedPub, err := os.ReadFile(pubFilnam)
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
    return &client, nil
}


// registers client with the acme server
func RegisterClient(ctx context.Context, client *acme.Client, contacts []string, dbg bool)(ac *acme.Account, err error) {

	var acntTpl acme.Account
	acntTpl.Contact = contacts

    acnt, err := client.Register(ctx, &acntTpl, acme.AcceptTOS)
    if err != nil { return nil, fmt.Errorf("client.Register: %v", err)}

    if dbg {
        log.Printf("success CA account generated\n")
        PrintAccount(acnt)
    }

    return acnt, nil
}

// generate cert names
func GenerateCertName(domain string)(certName string, err error) {

	domByt := []byte(domain)
	suc := false
	for i:=len(domByt)-1; i> 0; i-- {
		if domByt[i] == '.' {
			domByt[i] = '_'
			suc = true
			break
		}
	}
	if !suc {return "", fmt.Errorf("no extension with TLD found!")}

	certName = string(domByt)
	return certName, nil
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

// function to retrieve keys for LetsEncrypt acme account
func GetAcmeClient(acntFilnam string) (cl *acme.Client, err error) {

    var client acme.Client
	dbg :=false

	LEDir := os.Getenv("LEDir")
	if len(LEDir) == 0 {return nil, fmt.Errorf("cannot find LEDir!")}

	if len(acntFilnam) == 0 {
		return nil, fmt.Errorf("no account name provided\n")
	}
	if dbg {log.Printf("info -- account file: %s\n", acntFilnam)}

    acntData, err := os.ReadFile(acntFilnam)
    if err != nil {return nil, fmt.Errorf("cannot read account file! %v", err)}

    leAcnt := LEObj{}

    err = yaml.Unmarshal(acntData, &leAcnt)
    if err != nil {log.Fatalf("yaml Unmarshal account file: %v\n", err)}

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
//xxx
    return &client, nil
}

func CleanCsrFil (csrFilnam string, csrList *CsrList) (err error) {

    log.Printf("cleaning csr file\n")

    numAcmeDom := len(csrList.Domains)

    for i:= 0; i< numAcmeDom; i++ {
        domain := csrList.Domains[i]
        domain.ChalRecId = ""
        domain.Token = ""
        domain.TokVal = ""
        domain.TokUrl = ""
        domain.TokIssue = time.Time{}
        domain.TokExp = time.Time{}
		domain.OrderUrl = ""
        csrList.Domains[i] = domain
    }

    csrList.LastLU = time.Now()
	csrList.OrderUrl = ""
    err = WriteCsrFil(csrFilnam, csrList)
    if err != nil { return fmt.Errorf("certLib.WriteCsrFil: %v\n", err)}

//    log.Printf("success writing Csr File\n")

    return nil
}

func PrintCsrList(csrlist *CsrList) {

    fmt.Println("***************** Csr List *****************")
    fmt.Printf("Account: %s\n", csrlist.AcntName)
	if csrlist.LastLU.IsZero() {
		fmt.Printf("last mod: NA\n")
	} else {
		fmt.Printf("last mod: %s\n", csrlist.LastLU.Format(time.RFC1123))
	}
	fmt.Printf("orderUrl: %s\n", csrlist.OrderUrl)
	fmt.Printf("certUrl:  %s\n", csrlist.CertUrl)
    numDom := len(csrlist.Domains)
    fmt.Printf("domains:  %d\n", numDom)
    for i:=0; i< numDom; i++ {
        csrdat := csrlist.Domains[i]
		fmt.Printf("*****************************************\n")
        fmt.Printf("domain[%d]\n", i+1)
		fmt.Printf("===========\n")
		fmt.Printf("    name:      %s\n", csrdat.Domain)
        fmt.Printf("    email:     %s\n", csrdat.Email)
		fmt.Printf("    chal rec:  %s\n", csrdat.ChalRecId)
     	fmt.Printf("    token:     %s\n", csrdat.Token)
		fmt.Printf("    tokval:    %s\n", csrdat.TokVal)
		fmt.Printf("    tokUrl:    %s\n", csrdat.TokUrl)
		fmt.Printf("    orderUrl:  %s\n", csrdat.OrderUrl)
		fmt.Printf("    certUrl:   %s\n", csrdat.CertUrl)
		if csrdat.TokIssue.IsZero() {
			fmt.Printf("    tok issue:  NA\n")
		} else {
			fmt.Printf("    tok issue:  %s\n", csrdat.TokIssue.Format(time.RFC1123))
		}
		if csrdat.TokExp.IsZero() {
			fmt.Printf("    tok exp:    NA\n")
		} else {
			fmt.Printf("    tok exp:    %s\n", csrdat.TokExp.Format(time.RFC1123))
		}

	    fmt.Printf("    name:\n")
        nam:= csrdat.Name
        fmt.Printf("      CommonName:   %s\n", nam.CommonName)
        fmt.Printf("      Country:      %s\n", nam.Country)
        fmt.Printf("      Province:     %s\n", nam.Province)
        fmt.Printf("      Locality:     %s\n", nam.Locality)
        fmt.Printf("      Organisation: %s\n", nam.Organisation)
        fmt.Printf("      OrgUnit:      %s\n", nam.OrganisationUnit)
    }

    fmt.Println("******************* End Csr List ******************")

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

func PrintOrder(ord acme.Order) {
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

func PrintCsrReq(req *x509.CertificateRequest) {

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


func PrintCertObj(cert *certLibObj) {

	fmt.Printf("**************** certLibObj *****************\n")
	fmt.Printf("ZoneDir:     %s\n", cert.ZoneDir)
	fmt.Printf("CertDir:     %s\n", cert.CertDir)
	fmt.Printf("LE Dir:      %s\n", cert.LeDir)
	fmt.Printf("CF Dir:      %s\n", cert.CfDir)
	fmt.Printf("Csr Dir:    %s\n", cert.CsrDir)
	fmt.Printf("Cf Api File: %s\n", cert.CfApiFilnam)
	fmt.Printf("************** end certLibObj ***************\n")
}


