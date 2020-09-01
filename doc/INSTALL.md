# GTA Installation Instructions

## Prerequisites
1. Root permissions on the host 
2. trustagent_v1.0.0.bin makeself installer
3. TPM 2.0 device
4. RHEL 8.1 Host
5. Packages...
    1. tpm2-abrmd (v2.0.x)
    2. dmidecode (v3.x)
    3. redhat-lsb-core (v4.1.x)
    4. tboot (v1.9.7.x)
    5. compat-openssl10 (v1.0.x)
    6. logrotate

    `yum -y install tpm2-abrmd dmidecode redhat-lsb-core tboot compat-openssl10`

# Installation Steps
There are two methods for installing GTA.

|Type|Description|
|----|-----------|
|Minimal Install|The GTA makeself installer will perform a 'minimal install' when there is *not* a `trustagent.env` in the current directory. It only installs the GTA files and creates system users, services, etc.  At the completion of the minimal install, GTA must be provisioned and started to be integrated into the ISecL platform (see [Manual Provisioning](#Manual-Provisioning) below).|
|Automatic Provisioning|The GTA makeself installer will perform an 'automatic provisioning' when a valid `trustagent.env` file in the current directory.  'Automatic provisioning' will perform a 'Minimal Install' and configures GTA for integration with ISecL.  See [Automatic Provisioning Setup](#Automatic-Provisioning-Installation) below.|

In either case, steps to run the installer are:
1. Making sure the `trustagent-vX.Y.Z.bin` file is executable by the root user.
2. Running the installer as root: `sudo ./trustagent-vX.Y.Z.bin`.
Where X, Y, and Z represent the major/minor/patch release numbers.

*Note: By default, 'Application-Integrity' is installed with GTA and requires a reboot for measurements to be created.*

## Automatic Provisioning Installation
When there is a valid `trustagent.env` file in the current directory, the GTA makeself installer parses the file, export its values as environment variables and invokes `tagent setup`.  The following example demonstrates the contents of a valid `trustagent.env` file.

```
HVS_URL=https://{hvs_url}:{hvs_port}/hvs/v2
CMS_TLS_CERT_SHA384=7ff464fdd47192d7218e9bc7a80043641196762b840c5c79
BEARER_TOKEN=
TPM_OWNER_SECRET=625d6d8a18f98bf794760fd392b8c01be0b4e959
TRUSTAGENT_ADMIN_USERNAME=tagentadmin
TRUSTAGENT_ADMIN_PASSWORD=TAgentAdminPassword
GRUB_FILE=/boot/efi/EFI/redhat/grub.cfg
PROVISION_ATTESTATION=y
```
*For more information about the variables used in `trustagent.env` see [trustagent.env Reference](LLD.md#trustagent.env-Reference)*

When the 'automatic provisioning' installation is complete, GTA will be provisioned, running and ready to be registered with HVS.

## Manual Provisioning
When the installer completes a 'minimal install', the GTA files, users, services, etc. will be created on the host.  However, the GTA will not yet be configured to run.  To provision the host for integration into ISecl, `tagent setup` must be run.

Running `tagent setup` requires configuration information that is either defined in environment variables (similar to `trustagent.env`) or the `config.yml` file.

### Environment Variables
To run `tagent setup` manually with environment variables...
1. Export the required variables into the current shell (see the 'Required?' column at [trustagent.env Reference](LLD.md#trustagent.env-Reference)).
2. Run `tagent setup` as root.
3. Start tagent: `systemctl start tagent`

### config.yml
To run `tagent setup` with `config.yml`...
1. Create /opt/trustagent/configuration/config.yml, providing the required information (see [config.yml](LLD.md#config.yml)).
2. Run `tagent setup` as root.
3. Start tagent: `systemctl start tagent`