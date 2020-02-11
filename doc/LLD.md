# GTA Low Level Design (ISecl v2.0)
## Introduction
This is a low level design specification (LLD) of Go Trust Agent (GTA), which is a part of ISecLv2 development. This document describes is broken into four sections...

| Section | Description |
|---------|-------------|
| [Installation](#installation) | Describes how GTA deploys files, creates tagent user and other system artifacts.|
| [Setup](#setup) | Covers how GTA provisions the TPM, HVS and other depenencies in order to run as a service.|
| [Operations](#operations) | Describes how to start/stop GTA and register it with HVS to support features such as remote-attestation, asset tagging, etc..|
| [TrustAgent APIs](#trustagent-apis)|Lists the REST endpoints exposed by the GTA.|
| [Reference](#reference) | Miscellaneous tables and listings surrounding GTA's configuration files, environment variables, etc.|


*Note:  This document does not include details regarding the installation and operation of application-integity or workload-agent.*

# Installation
Installation is reponsible for deploying dependencies, GTA files, creating system users/services, etc.  GTA is distributed as a self extracting makeself/.bin file that supports the following use cases...

| Use Case | Description |
|----------|-------------|
|Minimal Install| The GTA makeself installer will perform a 'minimal install' when there is *not* a `trustagent.env` in the current directory (or when that file contains `PROVISION_ATTESTATION=n`). It only installs dependencies, the GTA files and creates users/services, etc.  After a minimal install, GTA must be provisioned via `tagent setup` and started to be integrated into the ISecL platform.|
|Automatic Provisioning| The GTA makeself installer will perform 'automatic provisioning' when a valid `trustagent.env` file in the current directory (and the file contains `PROVISION_ATTESTATION=y`).  'Automatic provisioning' will perform a 'Minimal Install' and also configures GTA for integration with ISecL.|
| Uninstall|  Allows the administrator to remove the GTA from the host.|

*For installation instructions see [INSTALL.md](INSTALL.md).*

## Minimal Install
During minimal installation, the installer performs the following activities...
1. Installs 3rd party software dependencies ([see Software Dependencies](#software-dependencies))
2. Creates the 'tagent' user, adding it to the 'tss' group so that it can access TPM (ex. /dev/tpm0)
3. Deploys the files for GTA.
5. Creates tagent systemd services.

*After a minimal install is completed, the administrator must provision the GTA and start the 'tagent' service.  See [Setup](#setup).*

## Automatic Provisioning
When the GTA installer is invoked with a valid `trustagent.env` file in the same directory (see [trustagent.env Reference](#trustagent.env-reference)), and that file contains `PROVISION_ATTESTATION=Y`, the installer will...
1. Perform the 'minimal installation' steps listed above.
2. Starts the `tpm2-abrmd` service to provision the TPM, AAS/CMS and HVS.
3. Invokes `tagent setup` (see [Setup](#setup) for more information).
4. Start the `tagent` service.

## Automatic Registration
When the GTA installer is invoked with a valid `trustagent.env` file in the same directory (see [trustagent.env Reference](#trustagent.env-reference)), and that file contains `AUTOMATIC_REGISTRATION=Y` as well as `PROVISION_ATTESTATION=Y`, the installer will...
1. Perform the 'minimal installation' steps listed above.
2. Perform the 'automatic provisioning' steps listed above.
3. Register the host with HVS by calling `tagent setup create-host` and `tagent setup create-host-unique-flavor`.

## Uninstall
After installation is completed, `tagent uninstall` can be run to remove the GTA.  Uninstall will...
1. Stop and disable the `tagent` service.
2. Uninstall `tboot-xm`.
3. Remove all files GTA files in `/opt/trustagent`.

# Setup
GTA exposes a command line interface (CLI) that supports 'setup'. Setup is the process of provisioning the GTA for use/integration in the ISecL platform.  Provisioning falls into three categories...

|Category|Description|
|--------|-----------|
|TPM Provisioning|Performs operations on the host's TPM to establish ownership and allocate keys/certs to support remote attestation. |
|AAS/CMS Provisioning|Provisions the TLS certificate, users and roles needed for ISecL microservices to access the GTA http endpoints.|
|HVS Provisioning|Interacts with HVS to establish authentication during remote-attestation.|

By default, the `tagent setup` command (or `tagent setup all`) is used during installation to provision the TPM, AAS/CMS and HVS and performs the tasks listed in the table below.  When completed successfully, GTA will be started as a service.  `tagent` will exit with an error code if any of the tasks fail. 

`tagent setup` executes the setup commands in the order listed below. 

|Task|Description|Results| Env Var(s)|
|----|-----------|-------|-----------|
|download-root-ca-cert|Downloads the root CA certificate from Certificate Management Service (CMS)|Creates a .pem file containing the Root CA certificate chain (root CA and Intermediate CA) in /opt/trustagent/configuration/cacerts/|CMS_BASE_URL, CMS_TLS_CERT_SHA384|
|download-ca-cert|Generates a asymmetric keypair and obtains the signed TLS certificate for Trust Agent webservice from Certificate CMS|Creates two files in /opt/trustagent/configuration: tls-key.pem containing the private key and tls-cert.pem containing the signed public key TLS cert signed by CMS|CMS_BASE_URL, TA_TLS_CERT_CN (optional), SAN_LIST, BEARER_TOKEN|
|download-privacy-ca|Downloads a certificate from HVS (/ca-certificates/privacy) which is used to encrypt data during 'provision-aik'. |Creates /opt/trustagent/configuration/privacy-ca.cer.|MTWILSON_API_URL, BEARER_TOKEN|
|take-ownership|Uses the value of TPM_OWNER_SECRET (or generates a new random secret) to take ownership of the TPM. |Takes ownership of the TPM and saves the secret key in /opt/trustagent/configuration/config.yml.  Fails if the TPM is already owned.|TPM_OWNER_SECRET|
|provision-ek|Validates the TPM's endorsement key (EK) against the list stored in HVS.|Validates the TPM's EK against the  manufacture certs downloaded from HVS (/ca-certificates?domain=ek).  Stores the manufacture EKs from HVS at /opt/trustagent/configuration/endorsement.pem.  Returns an error if the TPM EK is not valid.  Optionally registers the EK with HVS (if not present).|TPM_OWNER_SECRET, MTWILSON_API_URL, BEARER_TOKEN|
|provision-aik|Performs dark magic that provisions an AIK with HVS, supporting the ability to collect authenticated tpm quotes. |Generates an AIK secret key that is stored in /opt/trustagent/configuration/config.yml.  Creates /opt/trustagent/configuration/aik.cer that is hosted in the /aik endpoint.|TPM_OWNER_SECRET, MTWILSON_API_URL, BEARER_TOKEN|
|provision-primary-key|Allocates a primary key in the TPM used by WLA to create the binding/singing keys.|Allocates a new primary key in the TPM at index 0x81000000.|TPM_OWNER_SECRET|

*Note:  While GTA supports the option of independently executing the tasks below (ex. `tagent setup provision-ek`), it is not recommended due to complex ordering and interdependencies.*

# Operations
Provided the trust-agent has been installed and provisioned (aka 'setup'), administrators are then able to manage the service and register the host with HVS (to integrate the host into the ISecL platform). 

## Service Management
During installation, /opt/trustagent/tagent.service is created and enabled with systemd.  The following table shows the service commands for managing GTA...

|Action|Command|'systemctl' Command|
|------|-------|-----------------|
|Start tagent service|tagent start|`systemctl start tagent`|
|Stop tagent service|tagent stop|`systemctl stop tagent`|
|Get the status tagent service|tagent status|`systemctl status tagent`|
|Restart the tagent service|tagent restart|`systemctl restart tagent`|

Once the trust-agent is successfully operating under systemd, it will be restarted after system boot.

## HVS Registration/Configuration
Provided GTA service is running, the agent can be registered with HVS to support remote-attestation, asset-tagging, etc.  Registration entails adding the host to HVS' list of known hosts and establishing flavors for the host.  There are two ways to register the host with HVS...
1. 'CLI Initiated Registration' using GTA's command line interface (i.e. 'create-host')
2. 'HVS Initiated Registration' using HVS REST APIs.

### CLI Initiated Registration
1. Assume the GTA service is started and operational.
2. Execute `tagent setup create-host` to add the local host to HVS' list of known hosts.
3. Execute `tagent setup create-host-unique-flavor` to add the host's unique flavors to a flavor group in HVS.

### HVS Initiated Registration
1. Assume the GTA service is started and operational.
2. Use HVS' `/mtwilson/v2/hosts` (POST) to add the host to HVS' list of known hosts.
3. Use HVS' `/mtwilson/v2/flavors` (POST) to add the host's flavors to a flavor group in HVS.

Once registered/configured with HVS, the host will be available for quotes, asset tagging and other ISecL use cases.

# TrustAgent APIs

## AAS User/Roles

Authentication on the basis of stored credentials (BasicAuth) has been deprecated and going forward all Trust Agent APIs will use JSON Web Tokens (JWT) supplied the Authentication field of the request header to authenticate the source of the request.

The JWT tokens must be:

1. Currently valid - current server time on TA must be between *issued at (iat)* time and *expires at (eat)* time of JWT
2. Contain the permissions required by the API in Permissions field.
3. Signed by an known instance of Authentication and Authorization Service (AAS) configured at the the time of the deployment (using the **download-aas-jwt-cert** setup task).

The public certificate of the AAS instance will be provisioned to the TA service at the time of installation to ascertain JWT source's credibility and also validity (expiry time) and 

## /aik (GET)
    Description: The AIK is an asymmetric keypair generated by the host's Trusted Platform Module for the purpose of cryptographically securing attestation quotes for transmission to the Host Verification Server. The getAik REST API is used to retrieve the public Attestation Identity Key (AIK) certificate for the host.

    Authentication: Requires aik:retrieve permission 

    Input: None

    Output: 
        - Contents of /opt/trustagent/configuration/aik.cer (generated during provision-aik task) with Content-Type 'application/octet-stream'.      
        
        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.

## /host (GET)
    Description: Retrieves the host specific information (aka 'Platform-Info') from the host.

    Authentication: Requires host_info:retrieve permission

    Input: None

    Output: 
        - Contents of /opt/trustagent/var/system-info/platform-info with Content-Type 'application-json'.  Ex...

        {
            "errorCode": 0,
            "os_name": "RedHatEnterpriseServer",
            "os_version": "8.0",
            "bios_version": "SE5C620.86B.00.01.0014.070920180847",
            "vmm_name": "",
            "vmm_version": "",
            "processor_info": "54 06 05 00 FF FB EB BF",
            "host_name": "Purley32",
            "bios_name": "Intel Corporation",
            "hardware_uuid": "809797df-6d2d-e711-906e-0017a4403562",
            "processor_flags": "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge ...",
            "tpm_version": "2.0",
            "pcr_banks": [
                "SHA1",
                "SHA256"
            ],
            "no_of_sockets": "2",
            "tpm_enabled": "true",
            "txt_enabled": "true",
            "tboot_installed": "true",
            "is_docker_env": "false",
            "hardware_features": {
                "TPM": {
                    "enabled": true,
                    "meta": {
                        "tpm_version": "2.0",
                        "pcr_banks": "SHA1_SHA256"
                    }
                },
                "TXT": {
                    "enabled": true
                }
            },
            "installed_components": [
                "tagent"
            ]
        }
                
        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.



## /tag (POST)
    Description: Creates a new Asset Tag certificate in x509 format. Asset Tag certificates contain all key/value pairs to be tagged to a specific host, and the subject of the certificate is the hardware UUID of the host to be tagged.

    Authentication: Requires deploy_tag:create permission

    Input: json with the base64 encoded asset tag hash form HVS...
    
        {
            "tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
            "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
        }

    Output: 
        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.

## /tpm/quote (POST)
    Description: The TPM quote operation returns signed data and a signature. The data that is signed contains the PCRs selected for the operation, the composite hash for the selected PCRs, and a nonce provided as input, and used to prevent replay attacks. At provisioning time, the data that is signed is stored, not just the composite hash. The signature is discarded. This API is used to retrieve the AIK signed quote from TPM.

    Authentication: Requires quote:create permission

    Input: json containing HVS' 'nonce' and pcr/pcrbanks to collect in the quote.  Ex....
        { 
            "nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", 
            "pcrs": [0,1,2,3,18,19,22] , 
            "pcrbanks" : ["SHA1", "SHA256"]
        }

    Output: Quote data in xml format.  Ex...
        <tpm_quote_response>
            <timestamp>1574456312</timestamp>
            <clientIp>10.105.167.153</clientIp>
            <errorCode>0</errorCode>
            <errorMessage>OK</errorMessage>
            <aik>MIIDTTCCAbWgAwIBAgIGAW6UufKhMA0GCSqGSIb3DQEBCwUAMBsx...</aik>
            <quote>AIv/VENHgBgAIgALH32X9BG7tErCIvLz842c7hImJWx2IcBjyx7ngXTTwTwAF...</quote>
            <eventLog>PG1lYXN1cmVMb2cPHR4dD48dHh0U3RhdHVzPjM8L3R4dFN0YX...</eventLog>
            <tcbMeasurements>
                <tcbMeasurements>...</tcbMeasurements>
            </tcbMeasurements>
            <selectedPcrBanks>
                <selectedPcrBanks>SHA1</selectedPcrBanks>
                <selectedPcrBanks>SHA256</selectedPcrBanks>
            </selectedPcrBanks>
            <isTagProvisioned>true</isTagProvisioned>
            <assetTag>EtQNTJ3Lh1sgaaCRSncyMfbgzc1q9dor4snFY+9tvbhaWQ3m8MVnr1BsbzUIepJl</assetTag>
        </tpm_quote_response>
            
        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.

## /deploy/manifest (POST)
    Description: Allows users of HVS to deploy a list of directories/files (aka a 'manifest' in xml format) to establish 'Application Integrity'.

    Authentication: Requires deploy_manifest:create permission

    Input: XML Manifest...

        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Test_Application_Flavor_v1.0_TPM2.0" Uuid="b49f69a5-4fa1-4de2-afa7-629248894680" DigestAlg="SHA384">
            <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/someapp/bin"/>
            ...
            <File Path="/opt/someapp/scripts/.*" SearchType="regex"/>
        </Manifest>

    Output:  
        - Stores the manifest to /opt/trustagent/var/manifest-b49f69a5-4fa1-4de2-afa7-629248894680.xml
            
        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.


## /host/application-measurement (POST)
    Description: Measures application manifest provided as input, which is then used to generate software flavor.

    Authentication: Requires application_measurement:create permission

    Input:  XML Manifest...
    
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Test_Application_Flavor_v1.0_TPM2.0" Uuid="b49f69a5-4fa1-4de2-afa7-629248894680" DigestAlg="SHA384">
            <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/someapp/bin"/>
            ...
            <File Path="/opt/someapp/scripts/.*" SearchType="regex"/>
        </Manifest>

    Output:  
        - Returns the xml results of the measurement...

        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Test_Application_Flavor_v1.0_TPM2.0" Uuid="b49f69a5-4fa1-4de2-afa7-629248894680" DigestAlg="SHA384">
            <File Path="/opt/someapp/scripts/test.sh">0f47a757c86e91a3a175cd6ee597a67...</File>
            <CumulativeHash>cdff21f2be26b31a31143595a8aebed3ff44966df5e1...</CumulativeHash>
        </Measurement> 

        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.

## /binding-key-certificate (GET)
    Description: Retrieves the TPM binding key certificate to support the VM-C use case implemented in WLA.  This endpoint is operational when WLA has been installed an /host (platform-info) includes 'wlagent' in the list of 'installed_components'.

    Authentication: Requires **binding_key:retrieve** permission

    Input: None

    Output: 
        - Contents of /etc/workload-agent/bindingkey.pem (generated during WLA installation) with Content-Type 'application/octet-stream'.
                
        - Status: 200 on success, 400 with invalid input, 401 if not authorized, 500 for all other server errors.

## /version (GET)
    Description: Retrieves the version and build information for the Go Trust Agent.

    Authentication: None

    Input: None

    Output:             
        - Returns the contents of Version struct in util package - containing the build version and githash.

        - Status: 200 OK on response.

# Reference
The following sections are provided as a reference of GTA.

## CLI Options
|Option|Description| Required Env Var(s)|
|------|-----------|-----------|
|`tagent config aik.secret`|When populated in /opt/trustagent/configuration/config.yml, prints the aik secret key to stdout (supports WLA to create signing/binding keys.).||
|`tagent help`|Prints usage to stdout.||
|`tagent setup` or `tagent setup all`|Runs all setup tasks to provision the host to operate within ISecL (i.e. creates Root-CA/TLS certificates, provisions the TPM with HVS, etc.).  Also supports an option to use an answer file names `trustagent.env` (i.e. `tagent setup trustagent.env`) that will pass environment variables to GTA during setup.  [See Setup](#setup)||
|`tagent setup provision-attestation`|"Utility" command that provisions the TPM with HVS but does not perform other setup tasks.|MTWISLON_API_URL, BEARER_TOKEN|
|`tagent setup create-host`|Adds the local host to the list of HVS' known hosts.| MTWILSON_API_URL, BEARER_TOKEN|
|`tagent setup create-host-unique-flavor`|Registers the local hosts' unique flavor with HVS.| MTWILSON_API_URL, BEARER_TOKEN|
|`tagent setup get-configured-manifest`|Using environment variables, adds an application manifest from HVS to the local host to be measured at boot.  When invoked, the setup command will look for a comma seperated list of environment variables with the name 'FLAVOR_UUIDS' or 'FLAVOR_LABELS'.  It will then use that list to pull one or more manifest from HVS into the /opt/trustagent/var directory (so the manifest will be measured at next boot).  | MTWILSON_API_URL, BEARER_TOKEN, (FLAVOR_UUIDS or FLAVOR_LABELS)|
|`tagent setup download-ca-cert`|Downloads the latest Root-CA certificate from CMS to  `/opt/trustagent/configuration/cacerts`.| CMS_BASE_URL, SAN_LIST, TA_TLS_CERT_CN (optional), BEARER_TOKEN|
|`tagent setup download-cert`|Downloads TLS certs from CMS and updates the files in `/opt/trustagent/configuration` ( `tls-key.pem` and `tls-cert.pem`).| CMS_BASE_URL, SAN_LIST, TA_TLS_CERT_CN (optional), BEARER_TOKEN|
|`tagent setup update-certificates`|"Utility" command used to update the Root-CA and TLS cert.  Combines `tagent setup download-ca-cert` and `tagent setup downaload-ca`.|See `tagent setup download-ca-cert` and `tagent setup download-cert`.|
|`tagent start`|Starts the trust-agent service/http host similar to `systemctl status tagent`.||
|`tagent status`|Retrieves information about the trust-agent service/http host similar to `systemctl status tagent`.||
|`tagent stop`|Stops the trust-agent service/http host similar to `systemctl stop tagent`.||
|`tagent restart`|Restarts the trust-agent service/http host similar to `systemctl restart tagent`.||
|`tagent version`|Prints version information to stdout.  Ex. "```tagent v1.0.0-da14377 [2019-11-22T10:37:52-08:00]```".||
|`tagent version short`|Prints 'short' (major/minor) version information to stdout (to support the creation of application-integrity manifest files.) Ex. "```1.0```".||
|`tagent uninstall`|Uninstalls the trust-agent.  [See Uninstall](#uninstall)||

## trustagent.env Reference
If the GTA installer is run with a valid 'trustagent.env' file, it will parse the file's values and export them as environment variables that are then evaluated by `tagent setup`.  Below is a table of environment variables used by GTA...

| Env Var | Description | Example | Required?|Default|
|---------|-------------|---------|----------|-------|
|AAS_API_URL|API URL for Authentication Authorization Service (AAS).|AAS_API_URL=https://{host}:{port}/aas/v1|Yes|NA|
|AUTOMATIC_REGISTRATION|Automatically registers the host with HVS similar to `tagent setup create-host`.|AUTOMATIC_REGISTRATION=Y|No|N|
|BEARER_TOKEN|JWT from AAS that contains "install" permissions needed to access ISecL services during provisioning and registration.
|BEARER_TOKEN=eyJhbGciOiJSUzM4NCIsjdkMTdiNmUz...|Yes|NA|
|CMS_BASE_URL|API URL for Certificate Management Service (CMS).|CMS_BASE_URL=https://{host}:{port}/cms/v1|Yes|NA|
|CMS_TLS_CERT_SHA384|SHA384 Hash sum for verifying the CMS TLS certificate.|CMS_TLS_CERT_SHA384=bd8ebf5091289958b5765da4...|Yes|NA|
|MTWILSON_API_URL|The url used during setup to request information from HVS.|MTWILSON_API_URL=https://{host}:{port}/mtwilson/v2|Yes|NA|
|PROVISION_ATTESTATION|When present, enables/disables whether `tagent setup` is called during installation.  If trustagent.env is not present, the value defaults to no ('N').|PROVISION_ATTESTATION=Y|No|N|
|SAN_LIST|CSV list that sets the value for SAN list in the TA TLS certificate.  Defaults to 127.0.0.1.|SAN_LIST=10.123.100.1,201.102.10.22,mya.example.com|No|"127.0.0.1,localhost"|
|TA_TLS_CERT_CN|Sets the value for Common Name in the TA TLS certificate.  Defaults to CN=trustagent.|TA_TLS_CERT_CN=Acme Trust Agent 007|No|"Trust Agent TLS Certificate"|
|TPM_OWNER_SECRET|20 byte hex value to be used as the secret key when taking ownership of the TPM.  *Note: If this field is not specified, GTA will generate a random secret key.*|TPM_OWNER_SECRET=625d6...|No|""|
|TPM_QUOTE_IPV4|When enabled (`=y`), uses the local system's ip address as a salt when processing a quote nonce.  This field must align with the configuration of HVS.|TPM_QUOTE_IPV4=no|No|N|
|TA_SERVER_READ_TIMEOUT|Sets tagent server ReadTimeout.  Defaults to 30 seconds.|TA_SERVER_READ_TIMEOUT=30|No|30|
|TA_SERVER_READ_HEADER_TIMEOUT|Sets `tagent` server ReadHeaderTimeout.  Defaults to 30 seconds. |TA_SERVER_READ_HEADER_TIMEOUT=10|No|10|
|TA_SERVER_WRITE_TIMEOUT|Sets `tagent` server WriteTimeout.  Defaults to 10 seconds.|TA_SERVER_WRITE_TIMEOUT=10|No|10|
|TA_SERVER_IDLE_TIMEOUT|Sets `tagent` server IdleTimeout.  Defaults to 10 seconds.|TA_SERVER_IDLE_TIMEOUT=10|No|10|
|TA_SERVER_MAX_HEADER_BYTES|Sets `tagent` server MaxHeaderBytes.  Defaults to 1MB(1048576)|TA_SERVER_MAX_HEADER_BYTES=1048576|No|1 << 20|
|TA_ENABLE_CONSOLE_LOG|When set true, `tagent` logs are redirected to stdout. Defaults to false|TA_ENABLE_CONSOLE_LOG=true|No|false|
|TRUSTAGENT_LOG_LEVEL|The logging level to be saved in config.yml during installation ("trace", "debug", "info").|TRUSTAGENT_LOG_LEVEL=debug|No|info|
|TRUSTAGENT_PORT|The port on which the trust-agent service will listen.|TRUSTAGENT_PORT=10433|No|1443|

## Installed Files
The following files are present after installation, setup and measured launch.
```
/opt/trustagent/
+-- bin
¦   +-- module_analysis_da.sh
¦   +-- module_analysis_da_tcg.sh
¦   +-- module_analysis.sh
¦   +-- tagent
+-- cacerts
¦   +-- cacertfile.pem
+-- configuration
¦   +-- aik.cer
¦   +-- config.yml
¦   +-- endorsement.pem
¦   +-- tpm-version
¦   +-- tls-cert.pem
¦   +-- tls-key.pem
¦   +-- jwt
¦       +-- aasjwtcertfile.pem
+-- logs
¦   +-- trustagent.log
+-- tagent.service
+-- var
    +-- manifest_{uid}.xml
    +-- measureLog.xml
    +-- ramfs
    ¦   +-- pcr_event_log
    ¦   +-- measurement_{uid}.xml
    +-- system-info
        +-- platform-info
```

## Software Dependencies
The GTA installer will update the system with the following dependencies.

    1. tpm2-abrmd-2.1
    2. tpm2-tss-2.0
    2. dmidecode-3
    3. redhat-lsb-core-4.1
    4. tboot-1.9.7*
    5. compat-openssl10-1.0

\* tboot is only installed when sUEFI is not enabled.  

## config.yml
The GTA stores configuration information in /opt/trustagent/configuration/config.yml.  The contents of the file is based on environment variables (`trustagent.env`) provided during `tagent setup`.  The example below includes comments that correlate the configuration item to environment variables defined in `trustagent.env`.

```
tpmquoteipv4: true                          # TPM_QUOTE_IPV4
logging:
  loglevel: info                            # TRUSTAGENT_LOG_LEVEL
  logenablestdout: false                    # TA_ENABLE_CONSOLE_LOG
  logentrymaxlength: 300                    # LOG_ENTRY_MAXLENGTH
webservice:
  port: 1443                                # TRUSTAGENT_PORT
  readtimeout: 30s                          # TA_SERVER_READ_TIMEOUT
  readheadertimeout: 10s                    # TA_SERVER_READ_HEADER_TIMEOUT
  writetimeout: 10s                         # TA_SERVER_WRITE_TIMEOUT
  idletimeout: 10s                          # TA_SERVER_IDLE_TIMEOUT
  maxheaderbytes: 1048576                   # TA_SERVER_MAX_HEADER_BYTES
hvs:
  url: https://0.0.0.0:8443/mtwilson/v2     # MTWILSON_API_URL
tpm:
  ownersecretkey: 625d6d8...1be0b4e957      # TPM_OWNER_SECRET
  aiksecretkey: 59acd1367...edcbede60c      # NA, generated by setup
aas:
  baseurl: https://0.0.0.0:8444/aas/        # AAS_API_URL
cms:
  baseurl: https://0.0.0.0:8445/cms/v1      # CMS_BASE_URL
  tlscertdigest: 330086b3...ae477c8502      # CMS_TLS_CERT_SHA384
tls:
  certsan: 10.105.167.153,localhost         # SAN_LIST
  certcn: Trust Agent TLS Certificate       # TA_TLS_CERT_CN
```