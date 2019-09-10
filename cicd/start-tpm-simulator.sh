#!/bin/bash

# This script will start (or restar) the simulator and tpm2-abrm service on a 'gta-devel' container.
# Note:  The simulator is reset when started using the '-rm' option.

# stop tpm2-abrmd if running
systemctl status tpm2-abrmd 2>&1> /dev/null
if [ $? -eq 0 ]; then
    echo "==> STOPPING TPM2-ABRMD"
    systemctl stop tpm2-abrmd 2>&1> /dev/null
    sleep 3
fi

# stop simulator if running
simulator_pid=`pgrep tpm_server`
if [ $? -eq 0 ]; then
    echo "==> KILLING SIMULATOR: $simulator_pid"
    kill -9 $simulator_pid
fi

# restart the simulator with -rm to remove state of tpm
echo "==> STARTING SIMULATOR"
/simulator/src/tpm_server -rm &
sleep 3

echo "==> STARTING TPM2-ABRMD"
systemctl restart tpm2-abrmd  2>&1> /dev/null
sleep 3

systemctl status tpm2-abrmd 2>&1> /dev/null
if [ $? -ne 0 ]; then
    echo "==> ERROR:  tpm2-abrmd is not started"
else
    echo "==> OK"
fi
