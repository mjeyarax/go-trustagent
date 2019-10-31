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
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/platforminfo"
	"intel/isecl/go-trust-agent/resource"
	"intel/isecl/go-trust-agent/tasks"
	"intel/isecl/go-trust-agent/version"
)

func printUsage() {
	fmt.Println("Tagent Usage:")
}
 
func setupLogging() error {

	logFile, err := os.OpenFile(constants.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
 
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetLevel(config.GetConfiguration().LogLevel)

	return nil
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
	cmd:= exec.Command(constants.ModuleAnalysis)
	cmd.Dir = constants.BinDir
	results, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("module_analysis_sh error: %s", results)
	}

	log.Info("Successfully updated measureLog.xml")
	return nil
}

func printVersion() {

	if len(os.Args) > 2 && os.Args[2] == "short" {
		major, err := version.GetMajorVersion()
		if err != nil {
			panic(err)
		}

		minor, err := version.GetMinorVersion()
		if err != nil {
			panic(err)
		}

		fmt.Printf("%d.%d\n", major, minor)
	} else {
		fmt.Printf("tagent %s-%s [%s]\n", version.Version, version.GitHash, version.CommitDate)
	}
}
 
func main() {

	err := setupLogging()
	if err != nil {
		panic(err)
	}

	if len(os.Args) <= 1 {
		fmt.Printf("Invalid arguments: %s\n\n", os.Args)
		printUsage()
		os.Exit(1)
	}

	currentUser, _ := user.Current()
	cmd := os.Args[1]
	switch cmd {
	case "version":
		printVersion()
	case "start":

		// 
		// The legacy trust agent was a shell script that did work like creating platform-info,
		// measureLog.xml, etc.  The systemd service ran that script as root.  Now, systemd is
		// starting tagent (go exec) which shells out to module_anlaysis.sh to create measureLog.xml
		// (requires root permissions).  So, 'tagent start' is two steps...
		// 1.) There tagent.service runs as root and calls 'start'.  platform-info and measureLog.xml
		// are created under that account.
		// 2.) 'start' option then forks the service running as 'tagent' user.
		//
		if currentUser.Username != constants.RootUserName {
			fmt.Printf("'tagent start' must be run as root, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}
	
		err = updatePlatformInfo()
		if err != nil {
			log.Printf("There was an error creating platform-info: %s\n", err.Error())
		}

		err = updateMeasureLog()
		if err != nil {
			log.Printf("There was an error creating measureLog.xml: %s\n", err.Error())
		}

		tagentUser, err := user.Lookup(constants.TagentUserName)
		if err != nil {
			log.Errorf("Could not find user '%s'", constants.TagentUserName)
			os.Exit(1)
		}

		uid, err := strconv.ParseUint(tagentUser.Uid, 10, 32)
		if err != nil {
			log.Errorf("Could not parse tagent user uid '%s'", tagentUser.Uid)
			os.Exit(1)
		}

		gid, err := strconv.ParseUint(tagentUser.Gid, 10, 32)
		if err != nil {
			log.Errorf("Could not parse tagent user gid '%s'", tagentUser.Gid)
			os.Exit(1)
		}

		// take ownership of all of the files in /opt/trusagent before forking the 
		// tagent service
		_ = filepath.Walk(constants.HomeDir, func(fileName string, info os.FileInfo, err error) error {
			//log.Infof("Owning file %s", fileName)
			err = os.Chown(fileName, int(uid), int(gid))
			if err != nil {
				log.Errorf("Could not own file '%s'", fileName)
				return err
			}

			return nil
		})

		// spawn 'tagent startService' as the 'tagent' user
		cmd := exec.Command(constants.TagentExe, "startService")
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.Dir = constants.BinDir
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}

		err = cmd.Start()
		if err != nil {
			log.Errorf("%s error: %s", constants.TagentExe, err)
			os.Exit(1)
		}

	case "startService":
		if currentUser.Username != constants.TagentUserName {
			log.Errorf("'tagent startService' must be run as the agent user, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		if config.GetConfiguration().TrustAgentService.Port == 0 {
			panic("The port has not been set, 'tagent setup' must be run before 'start'")
		}

		// create and start webservice
		service, err := resource.CreateTrustAgentService(config.GetConfiguration().TrustAgentService.Port)
		if err != nil {
			panic(err)
		}

		service.Start()
	case "setup":
		if currentUser.Username != constants.RootUserName {
			log.Errorf("'tagent setup' must be run as root, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		var setupCommand string
		if(len(os.Args) > 2) {
			setupCommand = os.Args[2]
		} else {
			setupCommand = tasks.DefaultSetupCommand
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