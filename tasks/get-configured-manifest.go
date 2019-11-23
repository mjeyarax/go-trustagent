/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/xml"
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	"io/ioutil"
	"os"
	"strings"
)

type GetConfiguredManifest struct {
	manifestsClient    vsclient.ManifestsClient
	savedManifestFiles []string
}

func (task GetConfiguredManifest) saveManifest(manifestXml []byte) error {

	manifest := vsclient.Manifest{}
	err := xml.Unmarshal(manifestXml, &manifest)
	if err != nil {
		return err
	}

	if strings.Contains(manifest.Label, vsclient.DEFAULT_APPLICATION_FLAVOR_PREFIX) ||
		strings.Contains(manifest.Label, vsclient.DEFAULT_WORKLOAD_FLAVOR_PREFIX) {
		log.Infof("Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", manifest.Label)
		return nil
	}

	manifestFile := fmt.Sprintf("%s/manifest_%s.xml", constants.VarDir, manifest.UUID)
	err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
	if err != nil {
		return err
	}

	// keep track of which manifests were saved so they can be validated in 'Validate()'
	task.savedManifestFiles = append(task.savedManifestFiles, manifestFile)
	return nil
}

// Uses "FLAVOR_UUIDS" and "FLAVOR_LABELS" environment variables to download
// application manifests from VS.
func (task *GetConfiguredManifest) Run(c setup.Context) error {

	var err error
	var flavorUUIDs []string
	var flavorLabels []string

	envVar := os.Getenv(constants.FlavorUUIDs)
	if envVar != "" {
		tmp := strings.Split(envVar, ",")

		for _, uuid := range tmp {
			err = validation.ValidateUUIDv4(uuid)
			if err != nil {
				return fmt.Errorf("'%s' is not a valid uuid", uuid)
			}

			flavorUUIDs = append(flavorUUIDs, uuid)
		}
	}

	envVar = os.Getenv(constants.FlavorLabels)
	if envVar != "" {
		flavorLabels = strings.Split(envVar, ",")
	}

	if len(flavorUUIDs) == 0 && len(flavorLabels) == 0 {
		return fmt.Errorf("No manifests were specified via the '%s' or '%s' environment variables", constants.FlavorUUIDs, constants.FlavorLabels)
	}

	for _, uuid := range flavorUUIDs {
		manifestXml, err := task.manifestsClient.GetManifestXmlById(uuid)
		if err != nil {
			log.Errorf("An error occurred while getting manifest with id '%s': %s", uuid, err)
			continue
		}

		err = task.saveManifest(manifestXml)
		if err != nil {
			log.Errorf("An error occurred while saving manifest with id '%s': %s", uuid, err)
			continue
		}
	}

	for _, label := range flavorLabels {
		manifestXml, err := task.manifestsClient.GetManifestXmlByLabel(label)
		if err != nil {
			log.Errorf("An error occurred while getting manifest with label '%s': %s", label, err)
			continue
		}

		err = task.saveManifest(manifestXml)
		if err != nil {
			log.Errorf("An error occurred while saving manifest with label '%s': %s", label, err)
			continue
		}
	}

	return nil
}

func (task *GetConfiguredManifest) Validate(c setup.Context) error {

	missing := false

	for _, manifestFile := range task.savedManifestFiles {
		if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
			log.Errorf("Validation error: Could not validate manifest '%s' was created", manifestFile)
			missing = true
		}
	}

	if missing {
		return fmt.Errorf("One or manifest files were not created.")
	}

	log.Info("Setup: Get configured manifest was successful.")
	return nil
}
