# GTA Installation Instructions

## Prerequisites
1. trustagent_v1.0.0.bin installer from gitlab (see https://gitlab.devtools.intel.com/kentthom/go-trust-agent)
2. TPM 2.0 compute node with RHEL 8 Host and the following packages...
    1. tpm2-abrmd (v2.0.x)
    2. dmidecode (v3.x)
    3. redhat-lsb-core (v4.1.x)
    4. tboot (v1.9.7.x)
    5. compat-openssl10 (v1.0.x)

    Ex. `yum -y install tpm2-abrmd dmidecode redhat-lsb-core tboot compat-openssl10`

## Provisioning InformationDebug
The following (example) information needs to be provided in `trustagent.env` file.

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

## Instructions
1. Copy the trustagent_v1.0.0.bin file to the compute-node.
2. Copy the trustagent.env file in the same directory as the installer.
3. Change permissions on the installer if needed:`chmod +x trustagent_v1.0.0.bin`.
4. Run the installer: `./trustagent_v1.0.0.bin`.  With `PROVISION_ATTESTATION=y`, the installer will run `tagent setup` and start the tagent service.
5. Confirm that the service is up by running `systemctl status tagent.service`.  Additionally, the service can be validated by confirming that `curl --request GET --user <TRUSTAGENT_ADMIN_USERNAME>:< TRUSTAGENT_ADMIN_PASSWORD> https://<compute-node-ip>:1443/v2/host -k --noproxy "*"` returns valid host json.
6. Confirm that TPM Provisioning was successful...
    1. Verify the contents of the aik...
        1. `openssl x509 -inform der -in /opt/trustagent/configuration/aik.cer -out /tmp/aik.pem`.
        2. `openssl x509 -in /tmp/aik.pem -text -noout` shows `Issuer: CN = mtwilson-pca-aik`.
    2. Endorsement authority certificate is present at `/opt/trustagent/configuration/endorsements.pem`.
    3. TLS certifcates (tls-key.pem and tls-cert.pem) are present in `/opt/trustagent/configuration`.
    4. HVS' 'privacy-ca.cer' is present in `/opt/trustagent/configuration`.

## HVS Provisioning
Once GTA is up and running it can be registered with HVS (TBD)...



