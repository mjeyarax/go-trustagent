#!/bin/bash

# READ .env file
echo PWD IS $(pwd)
if [ -f ~/trustagent.env ]; then
    echo Reading Installation options from `realpath ~/trustagent.env`
    env_file=~/trustagent.env
elif [ -f ../trustagent.env ]; then
    echo Reading Installation options from `realpath ../trustagent.env`
    env_file=../cms.env
fi

if [ -n $env_file ]; then
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
    echo No .env file found
    PROVISION_ATTESTATION="false"
fi

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up TrustAgent user..."
id -u tagent 2> /dev/null || useradd tagent

echo "Installing TrustAgent Service..."

COMPONENT_NAME=tagent
PRODUCT_HOME=/opt/trustagent
BIN_PATH=$PRODUCT_HOME/bin
#DB_SCRIPT_PATH=$PRODUCT_HOME/cacerts
LOG_PATH=/var/log/trustagent
CONFIG_PATH=/etc/trustagent

mkdir -p $BIN_PATH && chown tagent:tagent $BIN_PATH/
cp $COMPONENT_NAME $BIN_PATH/ && chown tagent:tagent $BIN_PATH/*
chmod 750 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

#mkdir -p $DB_SCRIPT_PATH && chown cms:cms $DB_SCRIPT_PATH/

# Create configuration directory in /etc
mkdir -p $CONFIG_PATH && chown tagent:tagent $CONFIG_PATH
chmod 700 $CONFIG_PATH
chmod g+s $CONFIG_PATH

# Create jwt certs directory in config
#mkdir -p $CONFIG_PATH/jwt && chown cms:cms $CONFIG_PATH/jwt
#chmod 700 $CONFIG_PATH/jwt
#chmod g+s $CONFIG_PATH/jwt

#mkdir -p $CONFIG_PATH/root-ca && chown cms:cms $CONFIG_PATH/root-ca
#chmod 700 $CONFIG_PATH/root-ca
#chmod g+s $CONFIG_PATH/root-ca

# Create logging dir in /var/log
mkdir -p $LOG_PATH && chown tagent:tagent $LOG_PATH
chmod 761 $LOG_PATH
chmod g+s $LOG_PATH

# Install systemd script
cp trustagent.service $PRODUCT_HOME && chown tagent:tagent $PRODUCT_HOME/tagent.service && chown tagent:tagent $PRODUCT_HOME

# Enable systemd service
systemctl disable tagent.service > /dev/null 2>&1
systemctl enable $PRODUCT_HOME/tagent.service
systemctl daemon-reload

# check if setup should occur
if [ "${PROVISION_ATTESTATION,,}" == "false" ]; then
    echo "PROVISION_ATTESTATION is false, skipping setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup
    SETUPRESULT=$?
    if [ ${SETUPRESULT} == 0 ]; then 
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi
