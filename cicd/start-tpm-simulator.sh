#!/bin/bash

# This script will start (or restart) the simulator and tpm2-abrm service on a 'gta-devel' container.
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
    exit 1
else
    echo "==> OK"
fi

# WIP:  Try to populate the simulator with an EK cert
# from https://google.github.io/tpm-js/#pg_certificates

# Generate a public/private key pair
#openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out certificate.pem -keyout private.pem -subj "/C=US/ST=California/L=Folsom/O=intel/CN=tpmsimulator"

# convert the cert to der
#openssl x509 -outform der -in certificate.pem -out ek.crt

# save the der to 0x1c00002 using NvDefineSpace and NvWrite
#ekSize=`stat --printf="%s" ek.crt`
#tpm2_nvdefine -x 0x1c00002 -a 0x40000001 -s $ekSize -t 0x2000a # (ppwrite|writedefine|ppread|ownerread|authread|no_da|written|platformcreate)
#tpm2_nvwrite -x 0x1c00002 -a 0x40000001 -o 0 ek.crt