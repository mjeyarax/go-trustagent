# Go Trust Agent (GTA)


## Build Instructions
GTA uses the same build instructions as the `tpm-provider` (see the `tpm-provider` project for more details).  The following instructions assumed that `gta-devel` docker image and container have been created as described in `Building tpm-provider` in the `tpm-provider` project.

1. cd `/docker_host/go-trust-agent`
3. `make package`
4. tagent and trustagent*.bin will be in the `/out` subdirectory

Note: The `gta-devel` docker contianer can be used in this fashion to build GTA, but cannot be used to run `tpm2-abrmd` because it must run as a service under `systemd`.  See `Unit Testing and TPM Simulator` in the `tpm-provider` for instructions to run `systemd`, `tpm2-abrmd` and the TPM simulator in the `gta-devel` container.

# Installing GTA
See docs/INSTALL.md

# gta-devel Debugging Instructions

## Installing GTA on 'gta-devel'
To debug GTA in a 'gta-devel' container, it must run 'systemd' so that services that support http, tpm2-abrmd, dmidecode (for platform-info), etc. can run.

1. Start an container of `gta-devel` that runs `systemd`: `docker run --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v $(pwd):/docker_host -p 9443:1443 gta-devel /usr/sbin/init`
2. Use Docker/vscode to 'attach' to the container.
3. Change directory to where trustagent*.bin file exists.
4. Create a `trustagent.env` file...
    ```
    MTWILSON_API_URL=https://{hvs_url}:{hvs_port}/mtwilson/v2
    MTWILSON_TLS_CERT_SHA384=7ff464fdd47192d7218e9bc7a80043641196762b840c5c79
    MTWILSON_API_USERNAME=admin
    MTWILSON_API_PASSWORD=password
    TPM_OWNER_SECRET=625d6d8a18f98bf794760fd392b8c01be0b4e959
    TRUSTAGENT_ADMIN_USERNAME=tagentadmin
    TRUSTAGENT_ADMIN_PASSWORD=TAgentAdminPassword
    TRUSTAGENT_LOGIN_REGISTER=true
    CURRENT_IP={ip of compute-node}
    GRUB_FILE=/boot/efi/EFI/redhat/grub.cfg
    REGISTER_TPM_PASSWORD=y
    AUTOMATIC_PULL_MANIFEST=n
    PROVISION_ATTESTATION=y
    ```
5. Run `./trustagent_v1.0.0.bin`
6. Start the trustagent service: `systemctl start tagent`
7. Make sure the service is running: `systemctl status tagent` does not show errors.
8. Confirm the REST API is accessible: `curl --request GET --user user:password https://localhost:1443/v2/host -k --noproxy "*"` returns without error.


    





