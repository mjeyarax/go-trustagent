# Go Trust Agent (GTA)


## Build Instructions
 GTA uses 'Visual Studio Code Insiders' and docker containers to build on Windows/Linux.  Containers are required to support the integration of tpm2-tss and tpm2-abrmd (version 2.0), which has some limited distribution support (i.e. rpms are not avialable for RHEL7.6).

### Prerequisites
* Visual Studio Code - Insiders ('insiders' is used to support docker debuging)
* Docker
* golang

Building, debuging and ci/cd use the 'gta-devel' image defined in cicd/Dockerfile.  It currently uses Fedora 29 and includes tools for compiling go, c/c++, makeself, tpm2-tss, tpm2-abrmd, etc. The image also includes the tpm-simulator.

### Compiling GTA
1. Create the 'gta-devel' docker image...
    1. `cd cicd`
    2. `docker build --tag=gta-devel --build-arg http_proxy=<proxy-if-needed> https_proxy=<proxy-if-needed> .`
    3. `docker image ls` should show 'gta-devel'
2. Start a new instance of the container, mounting the code as `/docker_host` directory in the container
    1. `docker run -it -v $(pwd):/docker_host gta-devel /bin/bash`
    2. Configure git to access gitlab to resolve dependencies on other ISecL go libraries.
        1. `git config --global http.proxy http://proxy-us.intel.com:911`
        2. `git config --global https.proxy http://proxy-us.intel.com:911`
        3. `git config --global url."ssh://git@gitlab.devtools.intel.com:29418".insteadOf https://gitlab.devtools.intel.com`
        4. Create ssh keys in ~/.ssh (id_rsa and id_rsa.pub)
    3. `cd /docker_host`
    3. `make installer`
    4. tagent and trustagent*.bin will be in the `/out` subdirectory

# Installation
1. Start an container of `gta-devel` that runs `systemd`...
    * `docker run --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v $(pwd):/docker_host  gta-devel /usr/sbin/init`
2. Use Docker/vscode to 'attach' to the container.
3. Change directory to where trustagent*.bin file exists.
4. <ENV FILE CONFIGURATION>
5. Run `./trustagent_v1.0.0.bin`
6. Start the trustagent service: `systemctl start tagent`
7. Make sure the service is running: `systemctl status tagent` does not show errors.
8. Confirm the REST API is accessible: `curl --request GET http://localhost:8446/v2/aik -k --noproxy "*"` returns without error.

# Debugging Instructions

## TPM Simulator Setup TBD
## Golang debugging TBD


# GitLab-Runner Configuration
GTA is build and unit tested in gitlab at https://gitlab.devtools.intel.com/kentthom/go-trust-agent using Gitlab-Runners...

1. The gitlab runner needs to be a Linux host with Docker installed.
2. Make sure the 'gta-devel' docker image is created (see Compiling GTA above).
3. Install gitlab-runner (see https://docs.gitlab.com/runner/install/linux-manually.html)
4. Register using `gitlab-runner register` and providing the following values when prompted...
    1. Provide the url of gitlab
    2. Provide the token from the go-trust-agent project (available in Settings/CICD in gitlab)
    3. Provide a description of the runner
    4. Add `gta` for the tag (indicates support for building GTA)
    5. Provide `docker` for executor
    6. Provide `gta-devel` for default docker image
5. Edit /etc/gitlab-runner/config.toml to run 'gta-devel' image be adding `pull_policy = "true"` under `[[runners.docker]]`.
6. Restart the runner (`systemctl restart gitlab-runner`)



