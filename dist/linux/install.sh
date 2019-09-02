#--------------------------------------------------------------------------------------------------
#
#--------------------------------------------------------------------------------------------------
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
TRUSTAGENT_ENV_FILE=trustagent.env
TRUSTAGENT_SERVICE=tagent.service
TRUSTAGENT_BIN_DIR=$TRUSTAGENT_HOME/bin
TRUSTAGENT_LOG_DIR=$TRUSTAGENT_HOME/logs
TRUSTAGENT_CFG_DIR=$TRUSTAGENT_HOME/config

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Installer started from " $USER_PWD

if [ -f $USER_PWD/$TRUSTAGENT_ENV_FILE ]; then
    env_file=$USER_PWD/$TRUSTAGENT_ENV_FILE
elif [ -f ~/$TRUSTAGENT_ENV_FILE ]; then
    env_file=~/$TRUSTAGENT_ENV_FILE
fi

if [ -z "$env_file" ]; then
    echo No .env file found
    PROVISION_ATTESTATION="false"
else
    echo "Using env file " $env_file
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

echo "Starting trustagent installation..."

TRUSTAGENT_USERNAME=${TRUSTAGENT_USERNAME:-$DEFAULT_TRUSTAGENT_USERNAME}
if ! getent passwd $TRUSTAGENT_USERNAME 2>&1 >/dev/null; then
useradd --comment "Trust Agent User" --home $TRUSTAGENT_HOME --system --shell /bin/false $TRUSTAGENT_USERNAME
usermod --lock $TRUSTAGENT_USERNAME

# TODO:  GONNA NEED TO ASSIGN OWNERSHIP TO TPM...
#  # add tagent user to tss group
#  usermod -a -G tss $TRUSTAGENT_USERNAME

#  # enable and start the tpm2-abrmd service
#  systemctl enable tpm2-abrmd.service
#  systemctl start tpm2-abrmd.service
#fi

# setup directories...
mkdir -p $TRUSTAGENT_HOME
mkdir -p $TRUSTAGENT_BIN_DIR
mkdir -p $TRUSTAGENT_CFG_DIR
mkdir -p $TRUSTAGENT_LOG_DIR

cp $TRUSTAGENT_EXE $TRUSTAGENT_BIN_DIR/ 

# make a link in /usr/bin to tagent...
ln -sfT $TRUSTAGENT_BIN_DIR/$TRUSTAGENT_EXE /usr/bin/$TRUSTAGENT_EXE

# Install systemd script
cp $TRUSTAGENT_SERVICE $TRUSTAGENT_HOME 

# file ownership/permissions
chown -R $TRUSTAGENT_USERNAME:$TRUSTAGENT_USERNAME $TRUSTAGENT_HOME
chmod 755 $TRUSTAGENT_BIN/*

# Enable tagent service
systemctl disable $TRUSTAGENT_SERVICE > /dev/null 2>&1
systemctl enable $TRUSTAGENT_HOME/$TRUSTAGENT_SERVICE
systemctl daemon-reload

# TODO:  If the TrustAgent's port is below 1024, use authbind to establish permissons
# see https://blog.webhosting.net/how-to-get-tomcat-running-on-centos-7-2-using-privileged-ports-1024/
# This will require a change to the tagent.service as well.
#mkdir -p /etc/authbind/byport
#if [ ! -f /etc/authbind/byport/1443 ]; then
#    touch /etc/authbind/byport/1443
#    chmod 500 /etc/authbind/byport/1443
#    chown $TRUSTAGENT_USERNAME /etc/authbind/byport/1443
#fi

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
    echo "Automatic provisioning is disabled, the TrustAgent installation is complete."
    echo "You must use 'tagent setup' commands to complete provisioning (see tagent --help)."
    echo "The tagent service must also be started (systemctl start tagent)"
fi