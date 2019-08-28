/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package main
 
 import (
	 "io"
	 "os"
	 log "github.com/sirupsen/logrus"
	 "fmt"
	 "intel/isecl/go-trust-agent/resource"
 )
 
 func printUsage() {
	 fmt.Println("Tagent Usage:")
 }
 
 func setupLogging() {
	 logFile, err := os.OpenFile("trustagent.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	 if err != nil {
		 panic(err)
	 }
 
	 multiWriter := io.MultiWriter(os.Stdout, logFile)
	 log.SetOutput(multiWriter)
 }
 
 func main() {
	 setupLogging()
 
	 if len(os.Args) <= 1 {
		 printUsage()
		 os.Exit(1)
	 }
 
	 cmd := os.Args[1]
	 switch cmd {
	 case "start":
		 // TODO:  create moduleLog.xml, platform-info, etc.
 
		 // create and start webservice
		 service, err := resource.CreateTrustAgentService(8450)
		 if err != nil {
			 panic(err)
		 }
 
		 service.Start()
	 default:
		 printUsage()
	 }
 }