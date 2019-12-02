# GTA Low Level Design (ISecl v2.0)
## Introduction
This is a low level design specification of Go Trust Agent (GTA) which is a part of ISecLv2 development. This document describes the detailed working of GTA and is broken into four sections...

| Section | Description |
|---------|-------------|
| [Installation](#Installation) | Describes how GTA deploys files, creates tagent user and other system artifacts.|
| [Setup](#Setup) | Covers how GTA provisions the TPM, HVS and other depenencies in order to run as a service.|
| [Operations](#Operations) | Describes how to start/stop GTA and register it with HVS to support features such as remote-attestation, asset tagging, etc..|
| [Reference](#Reference) | Miscellaneous tables, listings, etc.|

See 'GTA High Level Design v1.0.docx'

*Note:  This document does not include details regarding the installation and operation of application-integity or workload-agent.*

# Installation
Installation is reponsible for ensuring the presence of 3rd party libraries, deploying GTA files, creating system users/services, etc.  GTA is distributed as a self extracting makeself/.bin file that supports the following two use cases...

KWT:  Installation constraints:  RHEL8, TSS...

| Use Case | Description |
|----------|-------------|
|Minimal Install| The GTA installer only deploys files and creates system users/services.  It does not attempt to provision the agent, which needs to be performed before operation.|
|Automatic Provisioning| The installer is invoked with the 'trustagent.env' file containing configuration information.  The installer will use that data to provision the agent with the TPM, HVS, AAS, CMS, etc.|
| Uninstall|  Allows the administrator to remove the GTA from the host.|

*For installation instructions see [install.md](install.md).*

## Minimal Install
During minimal installation, the installer performs the following activities...
1. Ensure that the system has the appropriate prerequisites ([see Software Dependencies](#Software-Dependencies)])
2. Creates the 'tagent' user, adding it to the 'tss' group so that it can access TPM (ex. /dev/tpm0)
3. Deploys the files for GTA.
4. Deploys application-integrity (tboot-xm, libwml).
5. Configures tpm2-abrmd and tagent systemd services.

*After a minimal install is completed, the administrator must provision the GTA and start the 'tagent' service.*

## Automatic Provisioning
When the GTA installer is invoked with a valid `trustagent.env` file in the same directory ([see trustagent.env file reference](#trustagent-env)), and that file contains `PROVISION_ATTESTATION=Y`, the installer will...
1. Perform the 'minimal installation' listed above.
2. Start the `tpm2-abrmd` service to provision the TPM, AAS/CMS and HVS.
3. Invoke `tagent setup`.
4. Start the `tagent` service.

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

By default, the `tagent setup` command (or `tagent setup all`) is used to provision the TPM, AAS/CMS and HVS and performs the tasks listed in the table below.  When completed successfully, GTA will be ready to started as a service.  `tagent` will exit with an error code if any of the tasks fail. 

|Task|Description|Results| Env Var(s)|
|----|-----------|-------|-----------|
|create-tls-keypair|Generates a TLS cert used for the GTA http endpoint host.|Creates tls-cert.pem and tls-key.pem in /opt/trustagent/configuration (for use by the http endpoint host).||
|download-privacy-ca|Downloads a certificate from HVS (/ca-certificates/privacy) which is used to encrypt data during 'provision-aik'. |Creates /opt/trustagent/configuration/privacy-ca.cer.|MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD|
|take-ownership|Uses the value of TPM_OWNER_SECRET (or generates a new random secret) to take ownership of the TPM. |Takes ownership of the TPM and saves the secret key in /opt/trustagent/configuration/config.yml.  Fails if the TPM is already owned.|TPM_OWNER_SECRET|
|provision-ek|Validates the TPM's endorsement key (EK) against the list stored in HVS.|Validates the TPM's EK against the  manufacture certs downloaded from HVS (/ca-certificates?domain=ek).  Stores the manufacture EKs from HVS at /opt/trustagent/configuration/endorsement.pem.  Returns an error if the TPM EK is not valid.  Optionally registers the EK with HVS (if not present).|TPM_OWNER_SECRET, MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD|
|provision-aik|Performs dark magic that provisions an AIK with HVS, supporting the ability to collect authenticated tpm quotes. |Generates an AIK secret key that is stored in /opt/trustagent/configuration/config.yml.  Creates /opt/trustagent/configuration/aik.cer that is hosted in the /aik endpoint.|TPM_OWNER_SECRET, MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD|
|provision-primary-key|Allocates a primary key in the TPM used by WLA to create the binding/singing keys.|Allocates a new primary key in the TPM at index 0x81000000.|TPM_OWNER_SECRET|

*Note:  While GTA supports the option of executing these tasks independently (ex. `tagent setup create-tls-keypair`), it is not recommended due to complex order and interdependencies.*

# Operations
Provided the trust-agent has been installed and provisioned (aka 'setup'), administrators are then able to manage the service and register the host with HVS (to integrate the host into the ISecL platform). 

## Service Management
During installation, /opt/trustagent/tagent.service is created and enabled with systemd.  Managing the tagent service is done via `systemctl`.  The following table shows the `systemctl` commands for managing GTA...

|Action|Command|
|------|-------|
|Start tagent service|`systemctl start tagent`|
|Stop tagent service|`systemctl stop tagent`|
|Get the status tagent service|`systemctl status tagent`|

Once the trust-agent is successfully operating under systemd, it will be restarted after reboots.

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

# Reference
The following sections are provided as a reference of GTA.

## TrustAgent APIs

### /aik (GET)
    Description: The AIK is an asymmetric keypair generated by the host's Trusted Platform Module for the purpose of cryptographically securing attestation quotes for transmission to the Host Verification Server. The getAik REST API is used to retrieve the public Attestation Identity Key (AIK) certificate for the host.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

    Input: None

    Output: Contents of /opt/trustagent/configuration/aik.cer (generated during provision-aik task) with Content-Type 'application/octet-stream'.

### /host (GET)
    Description: Retrieves the host specific information (aka “Platform-Info”) from the host.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

    Input: None

    Output: Contents of /opt/trustagent/var/system-info/platform-info with Content-Type 'application-json'.  Ex...

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



### /tag (POST)
    Description: Creates a new Asset Tag certificate in x509 format. Asset Tag certificates contain all key/value pairs to be tagged to a specific host, and the subject of the certificate is the hardware UUID of the host to be tagged.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

    Input: json with the base64 encoded asset tag hash form HVS...
    
        {
            "tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
            "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
        }

    Output: STATUS OK (200) on success.

### /tpm/quote (POST)
    Description: The TPM quote operation returns signed data and a signature. The data that is signed contains the PCRs selected for the operation, the composite hash for the selected PCRs, and a nonce provided as input, and used to prevent replay attacks. At provisioning time, the data that is signed is stored, not just the composite hash. The signature is discarded. This API is used to retrieve the AIK signed quote from TPM.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

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
    

### /deploy/manifest (GET)
    Description: Allows users of HVS to deploy a list of directories/files (aka a ‘manifest’ in xml format) to establish “Application Integrity”.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

    Input: XML Manifest...

        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Test_Application_Flavor_v1.0_TPM2.0" Uuid="b49f69a5-4fa1-4de2-afa7-629248894680" DigestAlg="SHA384">
            <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/someapp/bin"/>
            ...
            <File Path="/opt/someapp/scripts/.*" SearchType="regex"/>
        </Manifest>

    Output:  Stores the manifest to /opt/trustagent/var/manifest-b49f69a5-4fa1-4de2-afa7-629248894680.xml


### /host/application-measurement (POST)
    Description: Measures application manifest provided as input, which is then used to generate software flavor.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

    Input:  XML Manifest...
    
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Test_Application_Flavor_v1.0_TPM2.0" Uuid="b49f69a5-4fa1-4de2-afa7-629248894680" DigestAlg="SHA384">
            <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/someapp/bin"/>
            ...
            <File Path="/opt/someapp/scripts/.*" SearchType="regex"/>
        </Manifest>

    Output:  Performs the measurement and returns its xml...

        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Test_Application_Flavor_v1.0_TPM2.0" Uuid="b49f69a5-4fa1-4de2-afa7-629248894680" DigestAlg="SHA384">
            <File Path="/opt/someapp/scripts/test.sh">0f47a757c86e91a3a175cd6ee597a67...</File>
            <CumulativeHash>cdff21f2be26b31a31143595a8aebed3ff44966df5e1...</CumulativeHash>
        </Measurement> 

### /binding-key-certificate (GET)
    Description: Retrieves the TPM binding key certificate to support the VM-C use case implemented in WLA.  This endpoint is operational when WLA has been installed an /host (platform-info) includes 'wlagent' in the list of 'installed_components'.

    Authentication: TODO (currently requires basic auth using trust-agent username/password)

    Input: None

    Output: Contents of /etc/workload-agent/bindingkey.pem (generated during WLA installation) with Content-Type 'application/octet-stream'.

## CLI Options
|Option|Description| Required Env Var(s)|
|------|-----------|-----------|
|`tagent config aik.secret`|When populated in /opt/trustagent/configuration/config.yml, prints the aik secret key to stdout (supports WLA to create signing/binding keys.).||
|`tagent help`|Prints usage to stdout.||
|`tagent setup` or `tagent setup all`|Analogous to the legacy TA's "provision-attestation" command.  [See Setup](#Setup)||
|`tagent setup create-host`|Adds the local host to the list of HVS' known hosts.| MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD|
|`tagent setup create-host-unique-flavor`|Registers the local hosts' unique flavor with HVS.| MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD|
|`tagent setup get-configured-manifest`|Use environment variables, adds an application manifest from HVS to the local host to be measured at boot.  When invoked, the setup command will look for a comma seperated list of environment variables with the name 'FLAVOR_UUIDS' or 'FLAVOR_LABELS'.  It will then use that list to pull one or more manifest from HVS into the /opt/trustagent/var directory (so the manifest will be measured at next boot).  | MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD, (FLAVOR_UUIDS or FLAVOR_LABELS)|
|`tagent setup replace-tls-keypair`|Regenerates TLS certs by deleting `tls-key.pem` and `tls-cert.pem` from `/opt/trustagent/configuration` and reruns 'create-tls-keypair' command.| MTWILSON_API_URL, MTWILSON_API_USERNAME, MTWILSON_API_PASSWORD|
|`tagent start`|Starts the trust-agent service/http host. <p/>*This command should not be invoked directly.  Instead, use `systemctl` ([see Service Management](#Service-Management)).*||
|`tagent uninstall`|Uninstalls the trust-agent.  [See Uninstall](#Uninstall)||
|`tagent version`|Prints version information to stdout.  Ex. "```tagent v1.0.0-da14377 [2019-11-22T10:37:52-08:00]```".||
|`tagent version short`|Prints 'short' (major/minor) version information to stdout (to support the creation of application-integrity manifest files.) Ex. "```1.0```".||


## trustagent.env Reference
If the GTA installer is run with a valid 'trustagent.env' file, it will parse the file's values and export them as environment variables that are then evaluated by `tagent setup`.  Below is a table of environment variables used by GTA...

| Env Var | Description | Example | Required?|
|---------|-------------|---------|----------|
|MTWILSON_API_URL|The url used by GTA during setup to request information from HVS. |MTWILSON_API_URL=https://{host}:{port}/mtwilson/v2|Yes|
|MTWILSON_API_USERNAME|Basic authentication user name needed to access HVS endpoints.|MTWILSON_API_USERNAME=foo|Yes|
|MTWILSON_API_PASSWORD|Basic authentication password needed to access HVS endpoints.|MTWILSON_API_PASSWORD=bar|Yes|
|MTWILSON_TLS_CERT_SHA384|TLS cert hash from HVS.|MTWILSON_TLS_CERT_SHA384=6d8a18f...|Yes|
|PROVISION_ATTESTATION|When present, enables/disables whether `tagent setup` is called during installation.  If trustagent.env is not present, the value defaults to no ('N').|PROVISION_ATTESTATION=Y||
|TBOOTXM_INSTALL|Used by the makeself installer to determine if 'Application Integrity' should be installed.  Defaults to 'Y' (yes).  If set to 'N', 'Application Integrity' is not installed.|TBOOTXM_INSTALL=N||
|TPM_OWNER_SECRET|20 byte hex value to be used as the secret key when taking ownership of the tpm.  *Note: If this field is not specified, GTA will generate a random secret key.*|TPM_OWNER_SECRET=625d6...||
|TRUSTAGENT_ADMIN_PASSWORD|Basic authentication password needed to access GTA endpoints.|TRUSTAGENT_ADMIN_PASSWORD=gta_passwd|Yes|
|TRUSTAGENT_ADMIN_USERNAME|Basic authentication user name needed to access GTA endpoints.|TRUSTAGENT_ADMIN_USERNAME=gta_admin|Yes|
|TRUSTAGENT_PORT|Port to run `tagent` service.  Defaults to 1443.|TRUSTAGENT_PORT=8443||

*TODO:  Update when AAS/CMS is integrated.*

## AAS User/Roles (TBD)

## Installed Files
The following files are created on the host during a 'minimal installation'...
```
/opt/trustagent/
├── bin
│   ├── module_analysis_da.sh
│   ├── module_analysis_da_tcg.sh
│   ├── module_analysis.sh
│   └── tagent
├── configuration
│   └── tpm-version
├── logs
├── tagent.service
└── var
    ├── manifest_{uid}.xml
    ├── manifest_{uid}.xml
    ├── ramfs
    └── system-info
```

## Software Dependencies
For the ISecL v2.0 release, GTA will target RHEL 8.0 only.  The following dependencies must be present on the host for the installer to run.

    1. tpm2-abrmd-2.1
    2. tpm2-tss-2.0
    2. dmidecode-3
    3. redhat-lsb-core-4.1
    4. tboot-1.9.7
    5. compat-openssl10-1.0

## config.yml
The GTA stores configuration information in /opt/trustagent/configuration/config.yml.  The contents of the file is based on environment variables (`trustagent.env`) provided during `tagent setup`.  

```
loglevel: info
trustagentservice:
  port: 1443
  username: gta_user
  password: gta_password
hvs:
  url: https://127.0.0.1:8443/mtwilson/v2
  username: admin
  password: password
  tls384: a04d5fb42ab41dbcd5b68899d01ecf1884d79eeb8d36d080cebf3a5fc93f38d1382d7afbedb4fe1f48b95d0cff475a4b
tpm:
  ownersecretkey: 7fa014c4c8116678d0492eaae50625c514be416d
  aiksecretkey: 0492eaae50625c514be416d7fa014c4c8116678d
```
## Platform/Feature Matrix (TBD)
KWT/TODO

