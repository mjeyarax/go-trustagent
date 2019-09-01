#!/bin/bash

DEFAULT_TRUSTAGENT_HOME=/opt/trustagent
DEFAULT_TRUSTAGENT_USERNAME=tagent

export PROVISION_ATTESTATION=${PROVISION_ATTESTATION:-n}
export AUTOMATIC_PULL_MANIFEST=${AUTOMATIC_PULL_MANIFEST:-y}
export TRUSTAGENT_ADMIN_USERNAME=${TRUSTAGENT_ADMIN_USERNAME:-tagent-admin}
export REGISTER_TPM_PASSWORD=${REGISTER_TPM_PASSWORD:-y}
export TRUSTAGENT_LOGIN_REGISTER=${TRUSTAGENT_LOGIN_REGISTER:-true}
export TRUSTAGENT_HOME=${TRUSTAGENT_HOME:-$DEFAULT_TRUSTAGENT_HOME}

TRUSTAGENT_EXE=tagent
TRUSTAGENT_SERVICE=tagent.service
TRUSTAGENT_BIN_DIR=$TRUSTAGENT_HOME/bin
TRUSTAGENT_LOG_DIR=$TRUSTAGENT_HOME/log
TRUSTAGENT_CFG_DIR=$TRUSTAGENT_HOME/config

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

# READ .env file
echo PWD IS $(pwd)
if [ -f ~/trustagent.env ]; then
    echo Reading Installation options from `realpath ~/trustagent.env`
    env_file=~/trustagent.env
elif [ -f trustagent.env ]; then
    echo Reading Installation options from `realpath trustagent.env`
    env_file=trustagent.env
fi

if [ -n $env_file ]; then
    . $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
    echo No .env file found
    PROVISION_ATTESTATION="false"
fi

echo "Starting trustagent installation..."

echo "Setting up TrustAgent user..."
id -u tagent 2> /dev/null || useradd tagent

echo "Deploying tagent..."
mkdir -p $TRUSTAGENT_BIN_DIR && chown tagent:tagent $TRUSTAGENT_BIN_DIR/
cp $TRUSTAGENT_EXE $TRUSTAGENT_BIN_DIR/ && chown tagent:tagent $TRUSTAGENT_BIN_DIR/$TRUSTAGENT_EXE
chmod 750 $TRUSTAGENT_BIN_DIR/*

# make a link in /usr/bin to tagent...
ln -sfT $TRUSTAGENT_BIN_DIR/$TRUSTAGENT_EXE /usr/bin/$TRUSTAGENT_EXE

# Create configuration directory
#mkdir -p $TRUSTAGENT_CFG_DIR && chown tagent:tagent $TRUSTAGENT_CFG_DIR
#chmod 700 $TRUSTAGENT_CFG_DIR
#chmod g+s $TRUSTAGENT_CFG_DIR

# Create logging directory
#mkdir -p $TRUSTAGENT_LOG_DIR && chown tagent:tagent $TRUSTAGENT_LOG_DIR
#chmod 761 $TRUSTAGENT_LOG_DIR
#chmod g+s $TRUSTAGENT_LOG_DIR

# Install systemd script
cp $TRUSTAGENT_SERVICE $TRUSTAGENT_HOME && chown tagent:tagent $TRUSTAGENT_HOME/$TRUSTAGENT_SERVICE && chown tagent:tagent $TRUSTAGENT_HOME

# Enable systemd service
systemctl disable $TRUSTAGENT_SERVICE > /dev/null 2>&1
systemctl enable $TRUSTAGENT_HOME/$TRUSTAGENT_SERVICE
systemctl daemon-reload

if [[ "$PROVISION_ATTESTATION" == "y" || "$PROVISION_ATTESTATION" == "Y" || "$PROVISION_ATTESTATION" == "yes" ]]; then
    echo "Automatic provisioning is enabled, using mtwilson url " $MTWILSON_API_URL

    $TRUSTAGENT_EXE setup
    SETUPRESULT=$?
    if [ ${SETUPRESULT} == 0 ]; then 
        systemctl start $TRUSTAGENT_SERIVCE
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $TRUSTAGENT_SERIVCE 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $TRUSTAGENT_SERIVCE daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $TRUSTAGENT_SERIVCE\`"
            exit 1
        fi
        echo "$TRUSTAGENT_SERIVCE daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
else
    echo "Automatic provisioning is disabled, the TrustAgent installation is complete"
    echo "You must use 'tagent setup' commands to complete provisioning (see tagent --help)"
fi