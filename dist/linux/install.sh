#--------------------------------------------------------------------------------------------------
# T R U S T A G E N T   I N S T A L L E R
#
# Overall process:
# 1. Make sure the script is ready to be run (root user, dependencies installed, etc.).
# 2. Load trustagent.env if present and apply exports.
# 3. Create tagent user
# 4. Create directories, copy files and own them by tagent user.
# 5. Make sure tpm2-abrmd is started and deploy tagent service.
# 6. If 'automatic provisioning' is enabled (PROVISION_ATTESTATION=y), initiate 'tagent setup'. 
#    Otherwise, exit with a message that the user must provision the trust agent and start the
#    service.
#--------------------------------------------------------------------------------------------------
#!/bin/bash

#--------------------------------------------------------------------------------------------------
# Script variables
#--------------------------------------------------------------------------------------------------
DEFAULT_TRUSTAGENT_HOME=/opt/trustagent
DEFAULT_TRUSTAGENT_USERNAME=tagent

export PROVISION_ATTESTATION=${PROVISION_ATTESTATION:-n}
export AUTOMATIC_PULL_MANIFEST=${AUTOMATIC_PULL_MANIFEST:-y}
export TRUSTAGENT_ADMIN_USERNAME=${TRUSTAGENT_ADMIN_USERNAME:-tagentadmin}
export REGISTER_TPM_PASSWORD=${REGISTER_TPM_PASSWORD:-y}
export TRUSTAGENT_LOGIN_REGISTER=${TRUSTAGENT_LOGIN_REGISTER:-true}
export TRUSTAGENT_HOME=${TRUSTAGENT_HOME:-$DEFAULT_TRUSTAGENT_HOME}

TRUSTAGENT_EXE=tagent
TRUSTAGENT_ENV_FILE=trustagent.env
TRUSTAGENT_SERVICE=tagent.service
TRUSTAGENT_BIN_DIR=$TRUSTAGENT_HOME/bin
TRUSTAGENT_LOG_DIR=$TRUSTAGENT_HOME/logs
TRUSTAGENT_CFG_DIR=$TRUSTAGENT_HOME/configuration
TRUSTAGENT_VAR_DIR=$TRUSTAGENT_HOME/var
TRUSTAGENT_DEPENDENCIES=('tpm2-abrmd-2.0' 'dmidecode-3' 'redhat-lsb-core-4.1')
TPM2_ABRMD_SERVICE=tpm2-abrmd.service

#--------------------------------------------------------------------------------------------------
# 1. Script prerequisites
#--------------------------------------------------------------------------------------------------
echo "Starting trustagent installation from " $USER_PWD

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

# make sure tagent.service is not running or install won't work
systemctl status $TRUSTAGENT_SERVICE 2>&1 > /dev/null
if [ $? -eq 0 ]; then
    echo "Please stop the tagent service before running the installer"
    exit 1
fi

# make sure dependencies are installed
for i in ${TRUSTAGENT_DEPENDENCIES[@]}; do
    echo "Checking for dependency ${i}"
    rpm -qa | grep ${i} > /dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Dependency ${i} must be installed."
        exit 1
    fi
done

# make sure tpm2-abrmd service is installed
systemctl list-unit-files --no-pager | grep $TPM2_ABRMD_SERVICE > /dev/null
if [ $? -ne 0 ]; then
    echo "The tpm2-abrmd service must be installed"
    exit 1
fi

#--------------------------------------------------------------------------------------------------
# 2. Load environment variable file
#--------------------------------------------------------------------------------------------------
if [ -f $USER_PWD/$TRUSTAGENT_ENV_FILE ]; then
    env_file=$USER_PWD/$TRUSTAGENT_ENV_FILE
elif [ -f ~/$TRUSTAGENT_ENV_FILE ]; then
    env_file=~/$TRUSTAGENT_ENV_FILE
fi

if [ -z "$env_file" ]; then
    echo "The trustagent.env file was not provided, 'automatic provisioning' will not be performed"
    PROVISION_ATTESTATION="false"
else
    echo "Using environment file $env_file"
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

#--------------------------------------------------------------------------------------------------
# 3. Create tagent user
#--------------------------------------------------------------------------------------------------
TRUSTAGENT_USERNAME=${TRUSTAGENT_USERNAME:-$DEFAULT_TRUSTAGENT_USERNAME}
if ! getent passwd $TRUSTAGENT_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Trust Agent User" --home $TRUSTAGENT_HOME --system --shell /bin/false $TRUSTAGENT_USERNAME
    usermod --lock $TRUSTAGENT_USERNAME
fi

# to access tpm, abrmd, etc.
usermod -a -G tss $TRUSTAGENT_USERNAME

#--------------------------------------------------------------------------------------------------
# 4. Setup directories, copy files and own them
#--------------------------------------------------------------------------------------------------
mkdir -p $TRUSTAGENT_HOME
mkdir -p $TRUSTAGENT_BIN_DIR
mkdir -p $TRUSTAGENT_CFG_DIR
mkdir -p $TRUSTAGENT_LOG_DIR
mkdir -p $TRUSTAGENT_VAR_DIR
mkdir -p $TRUSTAGENT_VAR_DIR/system-info

cp $TRUSTAGENT_EXE $TRUSTAGENT_BIN_DIR/ 

# make a link in /usr/bin to tagent...
ln -sfT $TRUSTAGENT_BIN_DIR/$TRUSTAGENT_EXE /usr/bin/$TRUSTAGENT_EXE

# Install systemd script
cp $TRUSTAGENT_SERVICE $TRUSTAGENT_HOME 

# file ownership/permissions
chown -R $TRUSTAGENT_USERNAME:$TRUSTAGENT_USERNAME $TRUSTAGENT_HOME
chmod 755 $TRUSTAGENT_BIN/*

#--------------------------------------------------------------------------------------------------
# 5. Enable/configure services, etc.
#--------------------------------------------------------------------------------------------------
# make sure the tss user owns /dev/tpm0 or tpm2-abrmd service won't start (this file does not
# exist when using the tpm simulator, so check for its existence)
if [ -f /dev/tpm0 ]; then
    chown tss:tss /dev/tpm0
fi

# enable tpm2-abrmd service (start below if automatic provisioning is enabled)
systemctl enable $TPM2_ABRMD_SERVICE

# Enable tagent service
systemctl disable $TRUSTAGENT_SERVICE > /dev/null 2>&1
systemctl enable $TRUSTAGENT_HOME/$TRUSTAGENT_SERVICE
systemctl daemon-reload

#--------------------------------------------------------------------------------------------------
# 6. If automatic provisioning is enabled, do it here...
#--------------------------------------------------------------------------------------------------
if [[ "$PROVISION_ATTESTATION" == "y" || "$PROVISION_ATTESTATION" == "Y" || "$PROVISION_ATTESTATION" == "yes" ]]; then
    echo "Automatic provisioning is enabled, using mtwilson url $MTWILSON_API_URL"

    # make sure that tpm2-abrmd is running before running 'tagent setup'
    systemctl status $TPM2_ABRMD_SERVICE 2>&1 > /dev/null
    if [ $? -ne 0 ]; then
        echo "Starting $TPM2_ABRMD_SERVICE"
        systemctl start $TPM2_ABRMD_SERVICE 2>&1 > /dev/null
        sleep 3

        # todo:  in production we want to check that is is running, but in development
        # the simulator needs to be started first -- for now warn, don't error...
        systemctl status $TPM2_ABRMD_SERVICE 2>&1 > /dev/null
        if [ $? -ne 0 ]; then
            echo "WARNING: Could not start $TPM2_ABRMD_SERVICE"
        fi
    fi

    $TRUSTAGENT_EXE setup

    # this script is run by root, so own any setup generated files by 'tagent'
    chown -R $TRUSTAGENT_USERNAME:$TRUSTAGENT_USERNAME $TRUSTAGENT_HOME

    if [ $? -eq 0 ]; then         
        systemctl start $TRUSTAGENT_SERVICE
        echo "Waiting for $TRUSTAGENT_SERVICE to start"
        sleep 3

        systemctl status $TRUSTAGENT_SERVICE 2>&1 > /dev/null
        if [ $? -ne 0 ]; then
            echo "Installation completed with errors - $TRUSTAGENT_SERVICE did not start."
            echo "Please check errors in syslog using \`journalctl -u $TRUSTAGENT_SERVICE\`"
            exit 1
        fi

        echo "$TRUSTAGENT_SERVICE is running"
    else 
        echo "'$TRUSTAGENT_EXE setup' failed"
        exit 1
    fi
else
    echo ""
    echo "Automatic provisioning is disabled. You must use 'tagent setup' command to complete"
    echo "provisioning (see tagent --help). The tagent service must also be started using 'systemctl"
    echo "start tagent.service'"
fi

echo "Installation succeeded"