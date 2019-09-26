/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"os"
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

func (tpmQuoteResponse *TpmQuoteResponse) readAikAsPem() error {
	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		return err
	}

	aikBytes, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(aikBytes)
	if err != nil {
		return err
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}

	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}

	tpmQuoteResponse.Aik = string(pem.EncodeToMemory(&publicKeyBlock))
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

	tpmQuoteResponse.EventLog = base64.StdEncoding.EncodeToString(eventLogBytes)
	return nil
}

func (tpmQuoteResponse *TpmQuoteResponse) getQuote(tpmQuoteRequest *TpmQuoteRequest) error {

	// KWT: Validate tpmquote request values (nonce cannot be null, etc.)

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return err
	}

	defer tpmProvider.Close()

	quoteBytes, err := tpmProvider.GetTpmQuote(config.GetConfiguration().Tpm.AikSecretKey, tpmQuoteRequest.Nonce, tpmQuoteRequest.PcrBanks, tpmQuoteRequest.Pcrs)
	if err != nil {
		return err
	}

	//log.Infof("Quote[%x]: %s\n\n", len(quoteBytes), hex.EncodeToString(quoteBytes))
	tpmQuoteResponse.Quote = base64.StdEncoding.EncodeToString(quoteBytes)

	return nil
}

// func (tpmQuoteResponse *TpmQuoteResponse) getSelectedPcrBanks(tpmQuoteRequest *TpmQuoteRequest) error {
// 	// TODO:  return what was requested
// 	tpmQuoteResponse.SelectedPcrBanks.SelectedPcrBanks = []string {"SHA1", "SHA256"}
// 	return nil // TBD
// }

func (tpmQuoteResponse *TpmQuoteResponse) getTcbMeasurements() error {
	tpmQuoteResponse.TcbMeasurements.TcbMeasurements = []string {"",}
	return nil // TBD
}

func createTpmQuote(tpmQuoteRequest *TpmQuoteRequest) (*TpmQuoteResponse, error) {
	var err error

	tpmQuoteResponse := TpmQuoteResponse {}
	tpmQuoteResponse.TimeStamp = time.Now().Unix()

	// clientIp

	// aik --> read from disk and convert to PEM string
	err = tpmQuoteResponse.readAikAsPem()
	if err != nil {
		return nil, err
	}
	
	// get the quote from tpmprovider
	err = tpmQuoteResponse.getQuote(tpmQuoteRequest)
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

	// TODO:  Validate tpmQuoteRequest (nonce can't be empty, etc.)

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

	log.Debug(string(xmlOutput))

	if _, err := bytes.NewBuffer(xmlOutput).WriteTo(httpWriter); err != nil {
		log.Errorf("There was an error writing tpm quote: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
}