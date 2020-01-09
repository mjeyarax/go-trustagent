/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/go-trust-agent/config"
	consts "intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/clients"
	"intel/isecl/lib/common/crypt"
	commLog "intel/isecl/lib/common/log"
	csetup "intel/isecl/lib/common/setup"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// DownloadAASJWTCert is a setup task for setting roles in AAS
type DownloadAASJWTCert struct {
	Flags []string
	cfg   *config.TrustAgentConfiguration
}

// Run will run the AAS Connection setup task, but will skip if Validate() returns no errors
func (aasjwt DownloadAASJWTCert) Run(c csetup.Context) error {
	log.Trace("tasks/download_aas_jwtcert:Run() Entering")
	defer log.Trace("tasks/download_aas_jwtcert:Run() Leaving")

	var err error

	fmt.Println("Running setup task: download-aas-jwt-cert")

	fs := flag.NewFlagSet("download-aas-jwt-cert", flag.ExitOnError)
	force := fs.Bool("force", false, "force rerun of AAS config setup")

	err = fs.Parse(aasjwt.Flags)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup download-aas-jwt-cert: Unable to parse flags")
		return errors.New("tasks/download_aas_jwtcert:Run() Unable to parse flags")
	}

	if aasjwt.Validate(c) == nil && !*force {
		fmt.Println("setup download-aas-jwt-cert: setup task already complete. Skipping...")
		log.Info("tasks/download_aas_jwtcert:Run() AAS configuration config already setup, skipping ...")
		return nil
	}

	var aasURL string
	if aasURL, err = c.GetenvString(aasjwt.cfg.AAS.BaseURL, "AAS Server URL"); err != nil {
		return errors.Wrap(err, "tasks/download_aas_jwtcert:Run() AAS endpoint not set in environment")
	}

	if strings.HasSuffix(aasURL, "/") {
		aasjwt.cfg.AAS.BaseURL = aasURL
	} else {
		aasjwt.cfg.AAS.BaseURL = aasURL + "/"
	}

	aasjwt.cfg.Save()
	log.Info("tasks/aas:Run() AAS endpoint updated")

	//Fetch JWT Certificate from AAS
	err = fnGetJwtCerts(aasjwt.cfg.AAS.BaseURL)
	if err != nil {
		log.Tracef("%+v", err)
		return errors.Wrap(err, "tasks/download_aas_jwtcert:Run() Failed to fetch JWT Auth Certs")
	}

	log.Info("tasks/download_aas_jwtcert:Run() aasconnection setup task successful")
	return nil
}

// Validate checks whether or not the AAS Connection setup task was completed successfully
func (aas DownloadAASJWTCert) Validate(c csetup.Context) error {
	log.Trace("tasks/download_aas_jwtcert:Validate() Entering")
	defer log.Trace("tasks/download_aas_jwtcert:Validate() Leaving")

	_, err := os.Stat(consts.TrustedJWTSigningCertsDir)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/download_aas_jwtcert:Validate() JWT certificate directory does not exist")
	}

	isJWTCertExist := isPathContainPemFile(consts.TrustedJWTSigningCertsDir)

	if !isJWTCertExist {
		return errors.New("tasks/download_aas_jwtcert:Validate() AAS JWT certs not found")
	}

	return nil
}

func isPathContainPemFile(name string) bool {
	f, err := os.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()

	// read in ONLY one file
	fname, err := f.Readdir(1)

	// if EOF detected path is empty
	if err != io.EOF && len(fname) > 0 && strings.HasSuffix(fname[0].Name(), ".pem") {
		log.Trace("tasks/download_aas_jwtcert:isPathContainPemFile() fname is ", fname[0].Name())
		_, errs := crypt.GetCertFromPemFile(name + "/" + fname[0].Name())
		if errs == nil {
			log.Trace("tasks/download_aas_jwtcert:isPathContainPemFile() full path valid PEM ", name+"/"+fname[0].Name())
			return true
		}
	}
	return false
}

func fnGetJwtCerts(aasURL string) error {
	log.Trace("tasks/download_aas_jwtcert:fnGetJwtCerts() Entering")
	defer log.Trace("tasks/download_aas_jwtcert:fnGetJwtCerts() Leaving")
	url := aasURL + "noauth/jwt-certificates"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/x-pem-file")
	secLog.Debugf("tasks/download_aas_jwtcert:fnGetJwtCerts() Connecting to AAS Endpoint %s", url)

	hc, err := clients.HTTPClientWithCADir(consts.TrustedCaCertsDir)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_aas_jwtcert:fnGetJwtCerts() Error setting up HTTP client: %s", err.Error())
	}

	res, err := hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "tasks/download_aas_jwtcert:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "tasks/download_aas_jwtcert:fnGetJwtCerts() Error while reading response body")
	}

	err = crypt.SavePemCertWithShortSha1FileName(body, consts.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "tasks/download_aas_jwtcert:fnGetJwtCerts() Error in certificate setup")
	}

	return nil
}
