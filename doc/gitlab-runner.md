# GitLab-Runner Configuration
GTA is build and unit tested in gitlab at https://gitlab.devtools.intel.com/kentthom/go-trust-agent using Gitlab-Runners...

1. The gitlab runner needs to be a Linux host with Docker installed.
2. Make sure the 'gta-devel' docker image is created (see 'Compiling GTA' above).
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