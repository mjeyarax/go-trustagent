/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
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
	XMLName				 xml.Name	`xml:"tpm_quote_response"`
	TimeStamp			 int64		`xml:"timestamp"`
	ClientIp			 string		`xml:"clientIp"`
	ErrorCode			 int		`xml:"errorCode"`
	ErrorMessage		 string		`xml:"errorMessage"`
	Aik					 string		`xml:"aik"`
	Quote				 string		`xml:"quote"`
	EventLog			 string		`xml:"eventLog"`
	TcbMeasurements	struct {
		XMLName			 xml.Name	`xml:"tcbMeasurements"`
		TcbMeasurements	 []string	`xml:"tcbMeasurements"`
	}
	SelectedPcrBanks struct {
		XMLName			 xml.Name	`xml:"selectedPcrBanks"`
		SelectedPcrBanks []string	`xml:"selectedPcrBanks"`
	}
	IsTagProvisioned	 bool		`xml:"isTagProvisioned"`
	AssetTag			 string		`xml:"assetTag,omitempty"`
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

func getLocalIpAsString() (string, error) {

	addr, err := getLocalIpAddr()
	if err != nil {
		return "", err
	}

	// trim "/24" from addr if present
	ipString := addr.String()

	idx := strings.Index(ipString, "/")
	if(idx > -1) {
		ipString = ipString[:idx]
	}

	return ipString, nil
}

//
// This function attempts to create a byte array from the host's ip address.  This
// is used to create a sha1 digest of the nonce that will make HVS happpy.
//
func getLocalIpAsBytes() ([]byte, error) {

	addr, err := getLocalIpAddr()
	if err != nil {
		return nil, err
	}

	if ipnet, ok := addr.(*net.IPNet); ok {
		return ipnet.IP[(len(ipnet.IP) - 4):len(ipnet.IP)], nil
	}

	return nil, errors.New("Could not collect local ip bytes")
}

func getLocalIpAddr() (net.Addr, error) {

	var addr net.Addr

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if !strings.HasPrefix(ipnet.String(), "192.") {
					log.Debugf("Found local ip address %s", ipnet.String())
					addr = ipnet
					break
				}
			}
		}
	}

	if addr == nil {
		return nil, errors.New("Did not find the local ip address")
	}

	return addr, nil
}


// HVS generates a 20 byte random nonce that is sent in the tpmQuoteRequest.  However,
// HVS expects the response nonce (in the TpmQuoteResponse.Quote binary) to be hashed with the bytes
// of local ip address.  If this isn't performed, HVS will throw an error when the
// response is received.
// 
// Also, HVS takes into account the asset tag in the nonce -- it takes the ip hashed nonce
// and 'extends' it with value of asset tag (i.e. when tags have been set on the trust agent).
func (tpmQuoteResponse *TpmQuoteResponse) getNonce(hvsNonce []byte) ([]byte, error) {

	ipBytes, err := getLocalIpAsBytes()
	if err != nil {
		return nil, err
	}

	log.Debugf("Received HVS nonce '%s', raw[%s]", base64.StdEncoding.EncodeToString(hvsNonce), hex.EncodeToString(hvsNonce))

	// similar to HVS' SHA1.digestOf(hvsNonce).extend(ipBytes)
    hash := sha1.New()
    hash.Write(hvsNonce)
    taNonce := hash.Sum(nil)

    hash = sha1.New()
    hash.Write(taNonce)
    hash.Write(ipBytes)
	taNonce = hash.Sum(nil)

	log.Debugf("Used ip bytes '%s' to extend nonce to '%s', raw[%s]", hex.EncodeToString(ipBytes), base64.StdEncoding.EncodeToString(taNonce), hex.EncodeToString(taNonce))

	if tpmQuoteResponse.IsTagProvisioned {

		if tpmQuoteResponse.AssetTag == "" {
			return nil, errors.New("The quote is 'tag provisioned', but the tag was not provided")
		}

		// TpmQuoteResponse is used to share data with HVS and stores the asset tag
		// as base64 -- apply the raw bytes to the hash similar to HVS.
		tagBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.AssetTag)
		if err != nil {
			return nil, err
		}

		// similar to HVS' SHA1.digestOf(taNonce).extend(tagBytes)
		hash := sha1.New()
		hash.Write(taNonce)
		taNonce = hash.Sum(nil)

		hash = sha1.New()
		hash.Write(taNonce)
		hash.Write(tagBytes)
		taNonce = hash.Sum(nil)	

		log.Debugf("Used tag bytes '%s' to extend nonce to '%s', raw[%s]", hex.EncodeToString(tagBytes), base64.StdEncoding.EncodeToString(taNonce), hex.EncodeToString(taNonce))
	}

    return taNonce, nil
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

	nonce, err := tpmQuoteResponse.getNonce(tpmQuoteRequest.Nonce)
	if err != nil {
		return err
	}

	log.Debugf("Providing tpm nonce value '%s', raw[%s]", base64.StdEncoding.EncodeToString(nonce), hex.EncodeToString(nonce))

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return err
	}

	defer tpmProvider.Close()

	quoteBytes, err := tpmProvider.GetTpmQuote(config.GetConfiguration().Tpm.AikSecretKey, nonce, tpmQuoteRequest.PcrBanks, tpmQuoteRequest.Pcrs)
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

func (tpmQuoteResponse *TpmQuoteResponse) getAssetTags() error {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return err
	}

	defer tpm.Close()
	
	tagExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return err
	}

	if tagExists  {

		tpmQuoteResponse.IsTagProvisioned = true
		
		tagBytes, err := tpm.NvRead(config.GetConfiguration().Tpm.SecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return err
		} 

		tpmQuoteResponse.AssetTag = base64.StdEncoding.EncodeToString(tagBytes);	// this data will be evaluated in 'getNonce'

	} else {
		tpmQuoteResponse.IsTagProvisioned = false
	}
	
	return nil 
}

func createTpmQuote(tpmQuoteRequest *TpmQuoteRequest) (*TpmQuoteResponse, error) {
	var err error

	tpmQuoteResponse := TpmQuoteResponse {}
	tpmQuoteResponse.TimeStamp = time.Now().Unix()

	// getAssetTags must be called before getQuote so that the nonce is created correctly - see comments for getNonce()
	err = tpmQuoteResponse.getAssetTags()
	if err != nil {
		return nil, err
	}

	// get the quote from tpmprovider
	err = tpmQuoteResponse.getQuote(tpmQuoteRequest)
	if err != nil {
		return nil, err
	}

	// clientIp
	tpmQuoteResponse.ClientIp, err = getLocalIpAsString()
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

	tpmQuoteResponse.ErrorCode = 0				// Question: does HVS handle specific error codes or is just a pass through?
	tpmQuoteResponse.ErrorMessage = "OK"
	return &tpmQuoteResponse, nil
}

// curl --user tagentadmin:TAgentAdminPassword -d '{ "nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", "pcrs": [0,1,2,3,18,19,22] }' -H "Content-Type: application/json" -X POST https://localhost:1443/v2/tpm/quote -k --noproxy "*"
func getTpmQuote(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debug("getTpmQuote")

	var tpmQuoteRequest TpmQuoteRequest

	data, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Error reading request body: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(data, &tpmQuoteRequest)
	if err != nil {
		log.Errorf("Error marshaling json data: %s...\n%s", err, string(data))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(tpmQuoteRequest.Nonce) == 0 {
		log.Error("The TpmQuoteRequest does not contain a nonce")
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	} 

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

	httpWriter.Header().Set("Content-Type", "application/xml")
	httpWriter.WriteHeader(http.StatusOK)
	_, _ = bytes.NewBuffer(xmlOutput).WriteTo(httpWriter)
	return
}