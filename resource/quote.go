/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/tpmprovider"
)

// HVS expects...
// <tpm_quote_response>
//     <timestamp>1569264156635</timestamp>
//     <clientIp>fe80:0:0:0:a236:9fff:fef8:7229%enp134s0f1</clientIp>
//     <errorCode>0</errorCode>
//     <errorMessage>OK</errorMessage>
//     <aik>MIIDSjCCAbKgAwIBAgIGAWz...</aik>
//     <quote>AIv/VENHgBgAIgALUiWzd9...=</quote>
//     <eventLog>PG1lYXN1cmVMb2c+PHR4dD48dHh0U3RhdH...=</eventLog>
//     <tcbMeasurements>
//         <tcbMeasurements>&lt;?xml version="1.0" encoding="UTF-8" standalone="yes"?>&lt;Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Workload_Flavor_v2.0" Uuid="b13b405b-97a7-4480-a2e7-eea01f9799ce" DigestAlg="SHA384">&lt;CumulativeHash>000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000&lt;/CumulativeHash>&lt;/Measurement></tcbMeasurements>
// 			<...>
//     </tcbMeasurements>
//     <selectedPcrBanks>
//         <selectedPcrBanks>SHA1</selectedPcrBanks>
//         <selectedPcrBanks>SHA256</selectedPcrBanks>
//     </selectedPcrBanks>
//     <isTagProvisioned>false</isTagProvisioned>
// </tpm_quote_response>
type TpmQuoteResponse struct {
	XMLName				xml.Name	`xml:"tpm_quote_response"`
	TimeStamp			int64		`xml:"timestamp"`
	ClientIp			string		`xml:"clientIp"`
	ErrorCode			int			`xml:"errorCode"`
	ErrorMessage		string		`xml:"errorMessage"`
	Aik					string		`xml:"aik"`
	Quote				string		`xml:"quote"`
	EventLog			string		`xml:"eventLog"`
	TcbMeasurements	struct {
		XMLName				xml.Name	`xml:"tcbMeasurements"`
		TcbMeasurements		[]string 	`xml:"tcbMeasurements"`
	}
	SelectedPcrBanks	struct {
		XMLName				xml.Name	`xml:"selectedPcrBanks"`
		SelectedPcrBanks	[]string 	`xml:"selectedPcrBanks"`
	}
	IsTagProvisioned	bool		`xml:"isTagProvisioned"`
}

// HVS will provide json like...
// { 
//		"nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", 
//		"pcrs": [0,1,2,3,18,19,22],
//		"pcrbanks" : ["SHA1", "SHA256"] 
// }
type TpmQuoteRequest struct {
	Nonce				[]byte		`json:"nonce"`
	Pcrs				[]int		`json:"pcrs"`
	PcrBanks			[]string	`json:"pcrbanks"`
}

func (tpmQuoteResponse *TpmQuoteResponse) getLocalIpAddress() (string, error) {

	var localIp string
	
	localHost := "127.0.0.1"

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for i, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Warnf("Error reading interface index %d: %s", i, err)
		} else {
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
						ip = v.IP
				case *net.IPAddr:
						ip = v.IP
				}

				// only assign an Ip if it's not local host
				if ip.String() != localHost {
					localIp = ip.String()
					break
				}
			}
		}
	}

	if localIp == "" {
		return "", errors.New("Could not get local ip address")
	}

	return localIp, nil
}

//
// This function attempts to create a byte array from the host's ip address.  This
// is used to create a sha1 digest of the nonce that will make HVS happpy.
//
func getLocalIpAsBytes() ([]byte, error) {

	var ipBytes []byte

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				// ipnet.IP is padded with 0's, trim the last four bytes
				ipBytes = ipnet.IP[(len(ipnet.IP) - 4):len(ipnet.IP)]
				break
			}
		}
	}

	if ipBytes == nil {
		return nil, errors.New("Did not find an ip address")
	}

	return ipBytes, nil
}

// get's the local ip address in bytes and hashes the nonce/ip in a fashion acceptable
// to HVS's quote verifier.
func getIpHashedNonce(nonce []byte) ([]byte, error) {

	ipBytes, err := getLocalIpAsBytes()
	if err != nil {
		return nil, err
	}

    hash := sha1.New()
    hash.Write(nonce)
    b1 := hash.Sum(nil)

    hash = sha1.New()
    hash.Write(b1)
    hash.Write(ipBytes)
    b2 := hash.Sum(nil)

    return b2, nil
}

func (tpmQuoteResponse *TpmQuoteResponse) readAikAsBase64() error {
	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		return err
	}

	aikBytes, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		return err
	}

	tpmQuoteResponse.Aik = base64.StdEncoding.EncodeToString(aikBytes)
	return nil
}

func (tpmQuoteResponse *TpmQuoteResponse) readEventLog() error {
	if _, err := os.Stat(constants.MeasureLogFilePath); os.IsNotExist(err) {
		return err
	}

	eventLogBytes, err := ioutil.ReadFile(constants.MeasureLogFilePath)
	if err != nil {
		return err
	}

	// make sure the bytes are valid xml
	err = xml.Unmarshal(eventLogBytes, new(interface{}))
	if err != nil {
		return err
	}

	// this was needed to avoid an error in HVS parsing...
	// 'Current state not START_ELEMENT, END_ELEMENT or ENTITY_REFERENCE'
	xml := string(eventLogBytes)
	xml = strings.Replace(xml, " ", "", -1)
	xml = strings.Replace(xml, "\t", "", -1)
	xml = strings.Replace(xml, "\n", "", -1)

	tpmQuoteResponse.EventLog = base64.StdEncoding.EncodeToString([]byte(xml))
	return nil
}

func (tpmQuoteResponse *TpmQuoteResponse) getQuote(tpmQuoteRequest *TpmQuoteRequest) error {

	// HVS generates a 20 byte random nonce that is sent in the tpmQuoteRequest.  However,
	// HVS expects a nonce (in the TpmQuoteResponse.Quote binary) is that nonce hashed with the bytes
	// of local ip address.  If this isn't performed, HVS will throw an error when the
	// response is received.
	ipHashedNonce, err := getIpHashedNonce(tpmQuoteRequest.Nonce)
	if err != nil {
		return err
	}

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return err
	}

	defer tpmProvider.Close()

	quoteBytes, err := tpmProvider.GetTpmQuote(config.GetConfiguration().Tpm.AikSecretKey, ipHashedNonce, tpmQuoteRequest.PcrBanks, tpmQuoteRequest.Pcrs)
	if err != nil {
		return err
	}

	tpmQuoteResponse.Quote = base64.StdEncoding.EncodeToString(quoteBytes)

	return nil
}

// TBD: Application Integrity
func (tpmQuoteResponse *TpmQuoteResponse) getTcbMeasurements() error {
	//tpmQuoteResponse.TcbMeasurements.TcbMeasurements = []string {"",}
	return nil 
}

func createTpmQuote(tpmQuoteRequest *TpmQuoteRequest) (*TpmQuoteResponse, error) {
	var err error

	tpmQuoteResponse := TpmQuoteResponse {}
	tpmQuoteResponse.TimeStamp = time.Now().Unix()

	// get the quote from tpmprovider
	err = tpmQuoteResponse.getQuote(tpmQuoteRequest)
	if err != nil {
		return nil, err
	}

	// clientIp
	tpmQuoteResponse.ClientIp, err = tpmQuoteResponse.getLocalIpAddress()
	if err != nil {
		return nil, err
	}

	// aik --> read from disk and convert to PEM string
	err = tpmQuoteResponse.readAikAsBase64()
	if err != nil {
		return nil, err
	}
	
	// eventlog: read /opt/trustagent/var/measureLog.xml (created during ) --> needs to integrate with module_analysis.sh
	err = tpmQuoteResponse.readEventLog()
	if err != nil {
		return nil, err
	}

	// TODO:  Application integrity
	err = tpmQuoteResponse.getTcbMeasurements()
	if err != nil {
		return nil, err
	}

	// selected pcr banks (just return what was requested similar to java implementation)
	tpmQuoteResponse.SelectedPcrBanks.SelectedPcrBanks = tpmQuoteRequest.PcrBanks

	// TODO:  Based on asset tags
	tpmQuoteResponse.IsTagProvisioned = false

	tpmQuoteResponse.ErrorCode = 0				// Question: does HVS handle specific error codes or is just a pass through?
	tpmQuoteResponse.ErrorMessage = "OK"
	return &tpmQuoteResponse, nil
}

// curl --user tagentadmin:TAgentAdminPassword -d '{ "nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", "pcrs": [0,1,2,3,18,19,22] }' -H "Content-Type: application/json" -X POST https://localhost:1443/v2/tpm/quote -k --noproxy "*"
func getTpmQuote(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debug("getTpmQuote")

	httpWriter.Header().Set("Content-Type", "application/xml") 

	var tpmQuoteRequest TpmQuoteRequest

	data, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Error reading request body: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.Unmarshal(data, &tpmQuoteRequest)
	if err != nil {
		log.Errorf("Error marshaling json data: %s...\n%s", err, string(data))
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	// KWT:  Validate tpmQuoteRequest (nonce can't be empty, etc.)

	tpmQuoteResonse, err := createTpmQuote(&tpmQuoteRequest) 
	if err != nil {
		log.Errorf("There was an error creating the tpm quote: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	} 

	xmlOutput, err := xml.MarshalIndent(tpmQuoteResonse, "  ", "    ")
	if err != nil {
		log.Errorf("There was an error serializing the tpm quote %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := bytes.NewBuffer(xmlOutput).WriteTo(httpWriter); err != nil {
		log.Errorf("There was an error writing tpm quote: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
}