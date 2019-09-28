#!/usr/bin/env sh

#
# This script is included as reference as to how the tpmprovider was implemented on linux ontop
# TSS2.  It also include comments back to go code.
#
# This script simulates the TPM provisioning performed by GTA.  It is known to work on RHEL8,
# version 4.18.0-80.el8.x86_64, with the default tpm2 libraries installed...
# - tpm2-tools-3.1.1-4.el8.x86_64
# - tpm2-tss-2.0.0-4.el8.x86_64
# - tpm2-abrmd-2.0.0-3.el8.x86_64
# - tpm2-tss-devel-2.0.0-4.el8.x86_64
# - tpm2-abrmd-selinux-2.0.0-2.el8.noarch
#
# The TPM must be cleared before running.
#

OWNER_AUTH=hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
ENDORSE_AUTH=$OWNER_AUTH
LOCKOUT_AUTH=$OWNER_AUTH
EK_HANDLE=0x81010000
EK_PUB=./ek.pub
READPUBLIC_EK_PUB=./ek_readpublic.pub
AK_AUTH=hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef
AK_HANDLE=0x81018000
AK_PUB=./ak.pub
AK_NAME=./ak.name
CREDENTIAL=./credential.out
CREDENTIAL_ACTIVE=./credential_active.outtagent

#TCTI_STR="tabrmd:bus_type=session"
TCTI_STR="tabrmd"

#
# Initiated in tasks.take_ownership.go and implemented in 'take_ownership.c'
#
tpm2_takeownership --tcti=$TCTI_STR \
    --owner-passwd="$OWNER_AUTH" \
    --endorse-passwd="$ENDORSE_AUTH" \
    --lock-passwd="$LOCKOUT_AUTH"

#
# The following three commands are encapsulated in CreateAik() (in aik.c) which is called
# from tasks.provision_aik.go
#
tpm2_getpubek --tcti="$TCTI_STR" \
    --endorse-passwd="$ENDORSE_AUTH" \
    --owner-passwd="$OWNER_AUTH" \
    --handle="$EK_HANDLE" \
    --alg=rsa \
    --file="$EK_PUB"

# This is not needed in the c code since we assume the ek create in getpubek will be stored
# at a fixed handled.
tpm2_readpublic --tcti="$TCTI_STR" \
    --object="$EK_HANDLE" \
    --opu="$READPUBLIC_EK_PUB"

tpm2_getpubak --tcti="$TCTI_STR" \
    --endorse-passwd="$ENDORSE_AUTH" \
    --owner-passwd="$OWNER_AUTH" \
    --ek-handle="$EK_HANDLE" \
    --ak-handle="$AK_HANDLE" \
    --file="$AK_PUB" \
    --ak-name="$AK_NAME" \
    --alg=rsa \
    --digest-alg=sha1 \
    --sign-alg=rsassa

#
# The generation of secret data, 'make_credential' and 'activate_credential' are simulated here 
# -- the nonce creation is done by HVS, tasks.provision_aik.go uses 'ActivateCreation()' 
# (activate_credential.c) to decrypt that data during the HVS handshakes performed in 
#  tasks.provision_aik.go
#
SEC_DATA=secret.data
echo "12345678" > $SEC_DATA
file_size=`stat --printf="%s" $AK_NAME`
AK_NAME_STRING=`cat "$AK_NAME"  | xxd -p -c $file_size`

# this command craps all over my console: /dev/null
tpm2_makecredential --tcti="$TCTI_STR" \
    --enckey="$READPUBLIC_EK_PUB" \
    --sec="$SEC_DATA" \
    --name="$AK_NAME_STRING" \
    --out-file=$CREDENTIAL 2>&1 >/dev/null

tpm2_activatecredential --tcti="$TCTI_STR" \
    --endorse-passwd="$ENDORSE_AUTH" \
    --handle="$AK_HANDLE" \
    --key-handle="$EK_HANDLE" \
    --in-file="$CREDENTIAL" \
    --out-file="$CREDENTIAL_ACTIVE"

#
# This simulates a call to /tpm/quote (resource/quote.go) and requires that the aik is created (CreateAik) 
#
QUOTE_PCRLIST="0x04:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23+0x0B:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23"
QUOTE_QUALIFY="b4781f450103d7ea58804669ab77590bd38d98109929dc75d0b12b4d9b3593f9"
tpm2_quote --tcti="$TCTI_STR" \
    --ak-handle="$AK_HANDLE" \
    --sel-list="$QUOTE_PCRLIST" \
    --qualify-data=$QUOTE_QUALIFY
