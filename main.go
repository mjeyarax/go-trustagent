/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package main
 
 import (
	"io"
	"os"
	"fmt"

	log "github.com/sirupsen/logrus"

	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
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

	cfg, err := initConfiguration()
	if err != nil {
		//fmt.Printf("Error initializing configuration: %s\n", err)
		panic(err)
	}

	cmd := os.Args[1]
	switch cmd {
	case "start":
		// TODO:  create moduleLog.xml, platform-info, etc.

		// create and start webservice
		service, err := resource.CreateTrustAgentService(cfg.Port)
		if err != nil {
			panic(err)
		}

		service.Start()
	case "setup":
		var setupCommand string
		if(len(os.Args) == 2) {
			setupCommand = tasks.SetupAllCommand
		} else {
			setupCommand = os.Args[2]
		}

		registry, err := tasks.CreateTaskRegistry(cfg, os.Args)
		if err != nil {
			panic(err)
		}

		registry.RunCommand(setupCommand)

	default:
		printUsage()
	}
 }