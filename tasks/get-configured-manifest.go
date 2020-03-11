/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/xml"
	"fmt"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	"intel/isecl/lib/common/log/message"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type GetConfiguredManifest struct {
	clientFactory      vsclient.VSClientFactory
	savedManifestFiles []string		// internal task variable that tracks saved manifests (used in Validate())
}

func (task GetConfiguredManifest) saveManifest(manifestXml []byte) error {
	log.Trace("tasks/get-configured-manifest:saveManifest() Entering")
	defer log.Trace("tasks/get-configured-manifest:saveManifest() Leaving")
	
	manifest := vsclient.Manifest{}
	err := xml.Unmarshal(manifestXml, &manifest)
	if err != nil {
		log.WithError(err).Error("tasks/get-configured-manifest:saveManifest() Error while unmarshalling the manifest xml")
		return errors.New("Error while unmarshalling the manifest xml")
	}

	if strings.Contains(manifest.Label, vsclient.DEFAULT_APPLICATION_FLAVOR_PREFIX) ||
		strings.Contains(manifest.Label, vsclient.DEFAULT_WORKLOAD_FLAVOR_PREFIX) {
		log.Infof("tasks/get-configured-manifest:saveManifest() Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", manifest.Label)
		return nil
	}

	manifestFile := fmt.Sprintf("%s/manifest_%s.xml", constants.VarDir, manifest.UUID)
	err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
	if err != nil {
		log.WithError(err).Errorf("tasks/get-configured-manifest:saveManifest() Error while writing %s/manifest_%s.xml file", constants.VarDir, manifest.UUID)
		return errors.Errorf("Error while writing %s/manifest_%s.xml file", constants.VarDir, manifest.UUID)
	}

	// keep track of which manifests were saved so they can be validated in 'Validate()'
	task.savedManifestFiles = append(task.savedManifestFiles, manifestFile)
	return nil
}

// Uses "FLAVOR_UUIDS" and "FLAVOR_LABELS" environment variables to download
// application manifests from VS.
func (task *GetConfiguredManifest) Run(c setup.Context) error {
	log.Trace("tasks/get-configured-manifest:Run() Entering")
	defer log.Trace("tasks/get-configured-manifest:Run() Leaving")
	fmt.Println("Running setup task: get-configured-manifest")

	var err error
	var flavorUUIDs []string
	var flavorLabels []string

	manifestsClient, err := task.clientFactory.ManifestsClient()
	if err != nil {
		log.WithError(err).Error("tasks/get-configured-manifest:Run() Could not create manifests client")
		return err
	}

	envVar := os.Getenv(constants.FlavorUUIDs)
	if envVar != "" {
		if len(envVar) > constants.FlavorUUIDMaxLength{
			secLog.Errorf("%s tasks/get-configured-manifest:Run() values given in %s exceeds maximum length limit", message.InvalidInputBadParam, constants.FlavorUUIDs)
			return errors.New("Flavor UUID exceeds maximum length limit")
		}
		tmp := strings.Split(envVar, ",")

		for _, uuid := range tmp {
			err = validation.ValidateUUIDv4(uuid)
			if err != nil {
				secLog.Errorf("%s tasks/get-configured-manifest:Run() Flavor UUID:'%s' is not a valid uuid", message.InvalidInputBadParam, uuid)
				return errors.Errorf("Flavor UUID:'%s' is not a valid uuid", uuid)
			}

			flavorUUIDs = append(flavorUUIDs, uuid)
		}
	}

	envVar = os.Getenv(constants.FlavorLabels)
	if len(envVar) > constants.FlavorLabelsMaxLength{
		secLog.Errorf("%s tasks/get-configured-manifest:Run() values given in %s exceeds maximum length limit", message.InvalidInputBadParam, constants.FlavorLabels)
		return errors.New("Flavor labels exceeds maximum length limit")
	}

	if envVar != "" {
		flavorLabels = strings.Split(envVar, ",")
	}

	err = validation.ValidateStrings(flavorLabels)
	if err != nil {
		secLog.Errorf("%s tasks/get-configured-manifest:Run() Flavor Labels:'%s' are not valid labels", message.InvalidInputBadParam, constants.FlavorLabels)
		return errors.Errorf("Flavor Labels:'%s' are not valid labels", constants.FlavorLabels)
	}

	if len(flavorUUIDs) == 0 && len(flavorLabels) == 0 {
		return errors.Errorf("tasks/get-configured-manifest:Run() No manifests were specified via the '%s' or '%s' environment variables", constants.FlavorUUIDs, constants.FlavorLabels)
	}

	for _, uuid := range flavorUUIDs {
		manifestXml, err := manifestsClient.GetManifestXmlById(uuid)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while downloading manifest with id '%s'", uuid)
		}

		err = task.saveManifest(manifestXml)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while saving manifest with id '%s'", uuid)
		}
	}

	for _, label := range flavorLabels {
		manifestXml, err := manifestsClient.GetManifestXmlByLabel(label)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while downloading manifest with label '%s'", label)
		}

		err = task.saveManifest(manifestXml)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while saving manifest with label '%s'", label)
		}
	}

	return nil
}

func (task *GetConfiguredManifest) Validate(c setup.Context) error {
	log.Trace("tasks/get-configured-manifest:Validate() Entering")
	defer log.Trace("tasks/get-configured-manifest:Validate() Leaving")
	missing := false

	for _, manifestFile := range task.savedManifestFiles {
		if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
			log.Errorf("tasks/get-configured-manifest:Validate() Could not validate manifest '%s' was created", manifestFile)
			missing = true
		}
	}

	if missing {
		log.Errorf("tasks/get-configured-manifest:Validate() One or more manifest files were not created")
		return errors.New("One or more manifest files were not created.")
	}

	log.Info("tasks/get-configured-manifest:Validate() Get configured manifest was successful.")
	return nil
}
