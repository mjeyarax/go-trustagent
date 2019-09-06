/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package main
 
 import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"

	log "github.com/sirupsen/logrus"

	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/platforminfo"
	"intel/isecl/go-trust-agent/resource"
	"intel/isecl/go-trust-agent/tasks"
)
 
 func printUsage() {
	fmt.Println("Tagent Usage:")
 }
 
 func setupLogging() error {
	logFile, err := os.OpenFile(constants.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return err
	}
 
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)

	return nil
 }

 func initConfiguration() (*config.TrustAgentConfiguration, error) {
	var cfg config.TrustAgentConfiguration

	return &cfg, nil
 }

 func updatePlatformInfo() error {

	// make sure the system-info directory exists
	_, err := os.Stat(constants.SystemInfoDir)
	if err != nil {
		return err
	}

	// create the 'platform-info' file
	f, err := os.Create(constants.PlatformInfoFilePath)
	defer f.Close()
	if err != nil {
		return err
	}

	// collect the platform info
	platformInfo, err := platforminfo.GetPlatformInfo()
	if err != nil {
		panic(err)
	}

	// serialize to json
	b, err := json.Marshal(platformInfo)
	if err != nil {
		return err
	}

	_, err = f.Write(b)
	if err != nil {
		return err
	}

	log.Info("Successfully updated platform-info")
	return nil
 }

 func updateMeasureLog() error {

	log.Info("Successfully updated measure-log")
	return nil
 }
 
 func main() {
	err := setupLogging()
	if err != nil {
		//fmt.Printf("Error setting up logging: %s\n", err)
		panic(err)
	}
 
	if len(os.Args) <= 1 {
		fmt.Printf("Invalid arguments: %s\n\n", os.Args)
		printUsage()
		os.Exit(1)
	}

	currentUser, _ := user.Current()
	if currentUser.Username != constants.RootUserName && currentUser.Username != constants.TagentUserName {
		fmt.Printf("tagent cannot be run as user '%s'\n", currentUser.Username)
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "start":

		if config.GetConfiguration().TrustAgentService.Port == 0 {
			panic("The port has not been set, 'tagent setup' must be run before 'start'")
		}

		err = updatePlatformInfo()
		if err != nil {
			log.Printf("There was an error creating platform-info: %s\n", err.Error())
		}

		err = updateMeasureLog()
		if err != nil {
			log.Printf("There was an error creating measure-log: %s\n", err.Error())
		}

		// create and start webservice
		service, err := resource.CreateTrustAgentService(config.GetConfiguration().TrustAgentService.Port)
		if err != nil {
			panic(err)
		}

		service.Start()
	case "setup":
		var setupCommand string
		if(len(os.Args) > 2) {
			setupCommand = os.Args[2]
		} else {
			setupCommand = tasks.SetupAllCommand
		}

		registry, err := tasks.CreateTaskRegistry(os.Args)
		if err != nil {
			panic(err)
		}

		err = registry.RunCommand(setupCommand)
		if err != nil {
			panic(err)
		}

	default:
		printUsage()
	}
 }