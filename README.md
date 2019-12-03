# ISecL Go Trust Agent (GTA)
The Trust Agent resides on physical servers and enables both remote attestation and the extended chain of trust capabilities. The Trust Agent maintains ownership of the server's Trusted Platform Module, allowing secure attestation quotes to be sent to the Verification Service.

## Key features
- Provides host specific information
- Provides secure attestation quotes
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.0
- TPM 2.0 device
- Packages
    - tpm2-abrmd (v2.0.x)
    - dmidecode (v3.x)
    - redhat-lsb-core (v4.1.x)
    - tboot (v1.9.7.x)
    - compat-openssl10 (v1.0.x)
- Proxy settings if applicable

*See [docs/install.md](doc/install.md) for additional installation instructions.*

## Software requirements
- git
- go 11.4 or newer
- docker

# Build Instructions
GTA use the `tpm-provider` libary to acces the TPM 2.0 device.  The following instructions assume that `gta-devel` docker image and container have been created as described in the 'Build Instructions' section of the `tpm-provider` project (see the README.md in that project for more details).

1. cd `/docker_host/go-trust-agent`
3. `make package`
4. `tagent` and `trustagent-v1.0.0.bin` will be in the /out subdirectory

Note: The `gta-devel` docker contianer can be used in this fashion to build GTA, but cannot be used to run or debug GTA because `tpm2-abrmd` must run as a service under `systemd`.  See `Unit Testing and TPM Simulator` in the `tpm-provider` project for instructions to run `systemd`, `tpm2-abrmd` and the TPM simulator in the `gta-devel` container.

# Links
- [Installation instructions](doc/install.md)
- [GTA LLD](doc/LLD.md)
- https://01.org/intel-secl/