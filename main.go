// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/resource"
	"intel/isecl/go-trust-agent/tasks"
	"intel/isecl/go-trust-agent/util"
	commonExec "intel/isecl/lib/common/exec"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/lib/common/log/message"
	"intel/isecl/lib/common/validation"
	"intel/isecl/lib/platform-info/platforminfo"
	"intel/isecl/lib/tpmprovider"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

const (
	SYSTEMCTL_START   = "start"
	SYSTEMCTL_STOP    = "stop"
	SYSTEMCTL_STATUS  = "status"
	SYSTEMCTL_RESTART = "restart"
)

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("    tagent <command> [arguments]")
	fmt.Println("")
	fmt.Println("Available Commands:")
	fmt.Println("    help|-h|-help    Show this help message")
	fmt.Println("    setup [task]     Run setup task")
	fmt.Println("    uninstall        Uninstall tagent")
	fmt.Println("    version          Print build version info")
	fmt.Println("    start            Start the trustagent service")
	fmt.Println("    stop             Stop the trustagent service")
	fmt.Println("    status           Get the status of the trustagent service")
	fmt.Println("")
	fmt.Println("Available Tasks for setup:")
	fmt.Println("    tagent setup all (or with empty 3rd argument)")
	fmt.Println("        - Runs all setup tasks to provision the trustagent.")
	fmt.Println("    tagent setup trustagent.env")
	fmt.Println("        - Runs all setup tasks to provision the trustagent using the env")
	fmt.Println("          file path provided as 3rd argument.")
	fmt.Println("    tagent setup download-ca-cert")
	fmt.Println("        - Fetches the latest CMS Root CA Certificates, overwriting existing")
	fmt.Println("          files.")
	fmt.Println("    tagent setup download-cert")
	fmt.Println("        - Fetches a signed TLS Certificate from CMS, overwriting existing")
	fmt.Println("          files.")
	fmt.Println("    tagent setup update-certificates")
	fmt.Println("        - Runs 'download-ca-cert' and 'download-cert'")
	fmt.Println("    tagent setup provision-attestation")
	fmt.Println("        - Runs setup tasks assocated with HVS/TPM provisioning.")
	fmt.Println("    tagent setup create-host")
	fmt.Println("        - Registers the trustagent with the verification service.")
	fmt.Println("    tagent setup create-host-unique-flavor")
	fmt.Println("        - Populates the verification service with the host unique flavor")
	fmt.Println("    tagent setup get-configured-manifest")
	fmt.Println("        - Uses environment variables to pull application-integrity.")
	fmt.Println("          manifests from the verification service.")
	fmt.Println("")
}

func updatePlatformInfo() error {
	log.Trace("main:updatePlatformInfo() Entering")
	defer log.Trace("main:updatePlatformInfo() Leaving")
	// make sure the system-info directory exists
	_, err := os.Stat(constants.SystemInfoDir)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while checking the existence of %s", constants.SystemInfoDir)
	}

	// create the 'platform-info' file
	f, err := os.Create(constants.PlatformInfoFilePath)
	defer f.Close()
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while creating %s", constants.PlatformInfoFilePath)
	}

	// collect the platform info
	secLog.Infof("%s main:updatePlatformInfo() Trying to fetch platform info", message.SU)
	platformInfo, err := platforminfo.GetPlatformInfo()
	if err != nil {
		return errors.Wrap(err, "main:updatePlatformInfo() Error while fetching platform info")
	}

	// serialize to json
	b, err := json.Marshal(platformInfo)
	if err != nil {
		return errors.Wrap(err, "main:updatePlatformInfo() Error while serializing platform info")
	}

	_, err = f.Write(b)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while writing into File: %s", constants.PlatformInfoFilePath)
	}

	log.Info("main:updatePlatformInfo() Successfully updated platform-info")
	return nil
}

func updateMeasureLog() error {
	log.Trace("main:updateMeasureLog() Entering")
	defer log.Trace("main:updateMeasureLog() Leaving")

	secLog.Infof("%s main:updateMeasureLog() Running %s using system administrative privileges", message.SU, constants.ModuleAnalysis)
	cmd := exec.Command(constants.ModuleAnalysis)
	cmd.Dir = constants.BinDir
	results, err := cmd.Output()
	if err != nil {
		return errors.Errorf("main:updateMeasureLog() module_analysis_sh error: %s", results)
	}

	log.Info("main:updateMeasureLog() Successfully updated measureLog.xml")
	return nil
}

func printVersion() {

	if len(os.Args) > 2 && os.Args[2] == "short" {
		major, err := util.GetMajorVersion()
		if err != nil {
			fmt.Fprintf(os.Stderr,"Error while fetching Major version: %v \n", err)
			os.Exit(1)
		}

		minor, err := util.GetMinorVersion()
		if err != nil {
			fmt.Fprintf(os.Stderr,"Error while fetching Minor version: %v \n", err)
			os.Exit(1)
		}

		fmt.Printf("%d.%d\n", major, minor)
	} else {
		fmt.Printf("tagent %s-%s [%s]\n", util.Version, util.GitHash, util.CommitDate)
	}
}

func uninstall() error {

	// stop/disable tagent service (if installed and running)
	//
	// systemctl status tagent will...
	// return 4 if not present on the system
	// return 3 if stopped
	// return 0 if running
	//
	// If not present, do nothing
	// if stopped, remove
	// if running, stop and remove
	_, _, err := commonExec.RunCommandWithTimeout(constants.ServiceStatusCommand, 5)
	if err == nil {
		// installed and running, stop and disable
		_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceStopCommand, 5)
		_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableCommand, 5)
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 3 {
				// stopped, just disable
				_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableCommand, 5)
			} else if waitStatus.ExitStatus() == 4 {
				// do nothing if not installed
			} else {
				return errors.Errorf("main:uninstall() Service status returned unhandled error code %d", waitStatus.ExitStatus())
			}
		} else {
			return errors.Errorf("main:uninstall() An unhandled error occurred with the tagent service: %s", err)
		}
	}

	fmt.Println("TrustAgent service removed successfully")

	//
	// uninstall tbootxml (if uninstall script is present)
	//
	if _, err := os.Stat(constants.UninstallTbootXmScript); err == nil {
		_, _, err = commonExec.RunCommandWithTimeout(constants.UninstallTbootXmScript, 15)
		if err != nil {
			return errors.Errorf("main:uninstall() An error occurred while uninstalling tboot: %s", err)
		}
	}

	fmt.Println("Application-Agent removed successfully")

	//
	// remove all of tagent files (in /opt/trustagent/)
	//
	if _, err := os.Stat(constants.InstallationDir); err == nil {
		err = os.RemoveAll(constants.InstallationDir)
		if err != nil {
			log.Errorf("main:uninstall() An error occurred removing the trustagent files: %s", err)
		}
	}

	//
	// remove all of tagent files (in /var/log/trustagent)
	//
	if _, err := os.Stat(constants.LogDir); err == nil {
		err = os.RemoveAll(constants.LogDir)
		if err != nil {
			log.Errorf("main:uninstall() An error occurred removing the trustagent log files: %s", err)
		}
	}

	fmt.Println("TrustAgent files removed successfully")

	return nil
}

func main() {

	if len(os.Args) <= 1 {
		fmt.Fprintf(os.Stderr, "Invalid arguments: %s\n", os.Args)
		printUsage()
		os.Exit(1)
	}

	if err := validation.ValidateStrings(os.Args); err != nil {
		secLog.WithError(err).Errorf("%s main:main() Invalid arguments", message.InvalidInputBadParam)
		fmt.Fprintln(os.Stderr, "Invalid arguments")
		printUsage()
		os.Exit(1)
	}

	cfg, err := config.NewConfigFromYaml(constants.ConfigFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing configuration file %v \n", err)
		os.Exit(1)
	}

	currentUser, _ := user.Current()

	cmd := os.Args[1]
	switch cmd {
	case "version":
		printVersion()
	case "startService":

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

		cfg.LogConfiguration(cfg.Logging.LogEnableStdout)

		err = updatePlatformInfo()
		if err != nil {
			log.Errorf("main:main() Error while creating platform-info: %s\n", err.Error())
		}

		err = updateMeasureLog()
		if err != nil {
			log.Errorf("main:main() Error While creating measureLog.xml: %s\n", err.Error())
		}

		tagentUser, err := user.Lookup(constants.TagentUserName)
		if err != nil {
			log.Errorf("main:main() Could not find user '%s'", constants.TagentUserName)
			os.Exit(1)
		}

		uid, err := strconv.ParseUint(tagentUser.Uid, 10, 32)
		if err != nil {
			log.Errorf("main:main() Could not parse tagent user uid '%s'", tagentUser.Uid)
			os.Exit(1)
		}
		
		gid, err := strconv.ParseUint(tagentUser.Gid, 10, 32)
		if err != nil {
			log.Errorf("main:main() Could not parse tagent user gid '%s'", tagentUser.Gid)
			os.Exit(1)
		}

		// take ownership of all of the files in /opt/trusagent before forking the
		// tagent service
		_ = filepath.Walk(constants.InstallationDir, func(fileName string, info os.FileInfo, err error) error {
			//log.Infof("Owning file %s", fileName)
			err = os.Chown(fileName, int(uid), int(gid))
			if err != nil {
				log.Errorf("main:main() Could not own file '%s'", fileName)
				return err
			}

			return nil
		})

		_ = filepath.Walk(constants.LogDir, func(fileName string, info os.FileInfo, err error) error {
			err = os.Chown(fileName, int(uid), int(gid))
			if err != nil {
					log.Errorf("main:main() Could not own file '%s'", fileName)
					return err
			}

			return nil
		})
				
		// spawn 'tagent startService' as the 'tagent' user
		cmd := exec.Command(constants.TagentExe, "startWebService")
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.Dir = constants.BinDir
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		
		err = cmd.Start()
		if err != nil {
			log.Errorf("main:main() error while starting the command %s : %s", constants.TagentExe, err)
			os.Exit(1)
		}

	case "startWebService":
		if currentUser.Username != constants.TagentUserName {
			fmt.Printf("'tagent startWebService' must be run as the agent user, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		cfg.LogConfiguration(cfg.Logging.LogEnableStdout)

		// make sure the config is valid before starting the trust agent service
		err = cfg.Validate()
		if err != nil {
			log.Errorf("main:main() Error while validating the configuration file: %s", err)
			os.Exit(1)
		}

		tpmFactory, err := tpmprovider.NewTpmFactory()
		if err != nil {
			log.Errorf("main:main() Could not create the tpm factory %+v", err)
			os.Exit(1)
		}

		// create and start webservice
		service, err := resource.CreateTrustAgentService(cfg, tpmFactory)
		if err != nil {
			log.Errorf("main:main() Error while creating trustagent service %+v", err)
			os.Exit(1)
		}

		service.Start()

	case "start":
		cfg.LogConfiguration(cfg.Logging.LogEnableStdout)

		output, err := run_systemctl(SYSTEMCTL_START)
		if err != nil {
			fmt.Fprintln(os.Stderr, "An error occurred attempting to start the Trust Agent Service...")
			fmt.Fprintln(os.Stderr, output)
			os.Exit(1)
		}

		fmt.Println("Successfully started the Trust Agent Service")

	case "status":
		cfg.LogConfiguration(cfg.Logging.LogEnableStdout)

		// systemctl status returns an error code when the service is not running --
		// don't report an error, just show the results to the console in either case
		output, _ := run_systemctl(SYSTEMCTL_STATUS)
		fmt.Fprintln(os.Stdout, output)

	case "stop":
		cfg.LogConfiguration(cfg.Logging.LogEnableStdout)

		output, err := run_systemctl(SYSTEMCTL_STOP)
		if err != nil {
			fmt.Fprintln(os.Stderr, "An error occurred attempting to stop the Trust Agent Service...")
			fmt.Fprintln(os.Stderr, output)
			os.Exit(1)
		}

		fmt.Println("Successfully stopped the Trust Agent Service")

	case "setup":

		cfg.LogConfiguration(cfg.Logging.LogEnableStdout)
		// only apply env vars to config before starting 'setup' tasks

		if currentUser.Username != constants.RootUserName {
			log.Errorf("main:main() 'tagent setup' must be run as root, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		var setupCommand string
		var flags []string
		if len(os.Args) > 2 {
			if strings.Contains(os.Args[2], "trustagent.env"){
				sourceEnvFile(os.Args[2])
				setupCommand = tasks.DefaultSetupCommand
			} else{
				setupCommand = os.Args[2]
				flags = os.Args[2:]
			}
		} else {
			setupCommand = tasks.DefaultSetupCommand
		}

		err = cfg.LoadEnvironmentVariables()
		if err != nil{
			log.WithError(err).Error("Error loading environment variables")
			fmt.Fprintf(os.Stderr, "Error loading environment variables\n %v \n\n", err)
		}

		registry, err := tasks.CreateTaskRegistry(cfg, flags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while creating task registry \n Error: %s\n", err.Error())
			log.Errorf("main:main() Error while creating task registry %+v", err)
			os.Exit(1)
		}

		err = registry.RunCommand(setupCommand)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while running setup Command %s, \n Error: %s\n ", setupCommand, err.Error())
			log.Errorf("main:main() Error while running setup Command %s, %+v", setupCommand, err)
			os.Exit(1)
		}

	case "config":
		if len(os.Args) != 3 {
			fmt.Printf("'config' requires an additional parameter.\n")
		}

		cfg.PrintConfigSetting(os.Args[2])

	case "uninstall":
		err = uninstall()
		if err != nil {
			fmt.Fprintf(os.Stderr, "main:main() Error while running uninstalling trustagent %+v\n", err)
			os.Exit(1)
		}

	case "help":
		fallthrough
	case "-help":
		fallthrough
	case "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Invalid option: '%s'\n\n", cmd)
		printUsage()
	}
}

func sourceEnvFile(trustagentEnvFile string){
	fi, err := os.Stat(trustagentEnvFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s file does not exist", trustagentEnvFile)
		os.Exit(1)
	}

	fileSz := fi.Size()
	if fileSz == 0 || fileSz > constants.TrustAgentEnvMaxLength{
		fmt.Fprintf(os.Stderr, "%s file size exceeds maximum length: %d", trustagentEnvFile, constants.TrustAgentEnvMaxLength)
		os.Exit(1)
	}

    file, err := os.Open(trustagentEnvFile)
    if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open file: %s", trustagentEnvFile)
		os.Exit(1)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var envKeyPair []string
    for scanner.Scan() {
		if scanner.Text() == "" || strings.HasPrefix("#", scanner.Text()) {
			continue
		}

		envKeyPair = strings.Split(scanner.Text(), "=")
		os.Setenv(envKeyPair[0], envKeyPair[1]) 
    }
}

func run_systemctl(systemCtlCmd string) (string, error) {
	log.Trace("main:run_systemctl() Entering")
	defer log.Trace("main:run_systemctl() Leaving")

	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error trying to look up for systemctl path")
		log.WithError(err).Error("main:run_systemctl() Error trying to look up for systemctl path")
		log.Tracef("%+v", err)
		os.Exit(1)
	}

	log.Infof("main:run_systemctl() Running 'systemctl %s tagent'", systemCtlCmd)

	cmd := exec.Command(systemctl, systemCtlCmd, "tagent")
	out, err := cmd.CombinedOutput()
	if err != nil && systemCtlCmd != SYSTEMCTL_STATUS {
		log.WithError(err).Errorf("main:run_systemctl() Error running 'systemctl %s tagent'", systemCtlCmd)
		log.Tracef("%+v", err)
		return string(out), err
	}

	return string(out), nil
}
