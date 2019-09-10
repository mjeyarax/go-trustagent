/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

//-------------------------------------------------------------------------------------------------
// E V I C T   C O N T R O L
// From https://raw.githubusercontent.com/tpm2-software/tpm2-tools/3.1.0/tools/tpm2_evictcontrol.c
//-------------------------------------------------------------------------------------------------
static int evict_control(TSS2_SYS_CONTEXT* sys, TPM2B_AUTH* newSecretKey, TPM2_HANDLE handle2048rsa) 
{
    TSS2_RC                 rval;
    TPMI_DH_OBJECT          persist = 0x81000000;    // fixed location for ISecL
    TSS2L_SYS_AUTH_COMMAND  sessionsData = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    sessionsData.count = 1;
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    memcpy(&sessionsData.auths[0].hmac, newSecretKey, sizeof(TPM2B_AUTH));
    sessionsData.auths[0].sessionAttributes = 0;

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, handle2048rsa, &sessionsData, persist, &sessionsDataOut);
    if (rval == TPM2_RC_SUCCESS) 
    {
        DEBUG("Evict Control was successfull")
    }
    else
    {
        ERROR("Evict Control failed: 0x%x", rval);
    }

    return rval;
}

//-------------------------------------------------------------------------------------------------
// T A K E   O W N E R S H I P
// From https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_takeownership.c
//-------------------------------------------------------------------------------------------------
static int clear_hierarchy_auth(TSS2_SYS_CONTEXT* sys, TPM2B_AUTH* oldSecretKey) 
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_COMMAND  sessionsData = {0};

    sessionsData.count = 1;
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    memcpy(&sessionsData.auths[0].hmac, oldSecretKey, sizeof(TPM2B_AUTH));
    sessionsData.auths[0].sessionAttributes = 0;

    rval = Tss2_Sys_Clear(sys, TPM2_RH_LOCKOUT, &sessionsData, 0);
    if (rval == TPM2_RC_SUCCESS) 
    {
        DEBUG("Clear Hierarchy was successfull")
    }
    else
    {
        ERROR("Clear Hierarchy failed: 0x%x", rval);
    }

    return rval;
}


static int change_auth(TSS2_SYS_CONTEXT* sys,
                       TPM2B_AUTH* newSecretKey, 
                       TPM2B_AUTH* oldSecretKey, 
                       const char* desc,
                       TPMI_RH_HIERARCHY_AUTH auth_handle) 
{

    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_COMMAND  sessionsData = {0};

    sessionsData.count = 1;
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    memcpy(&sessionsData.auths[0].hmac, oldSecretKey, sizeof(TPM2B_AUTH));
    sessionsData.auths[0].sessionAttributes = 0;

    rval = Tss2_Sys_HierarchyChangeAuth(sys, auth_handle, &sessionsData, newSecretKey, 0);
    if (rval == TPM2_RC_SUCCESS) 
    {
        DEBUG("Successfully changed hierarchy for %s", desc);
    }
    else
    {
        ERROR("Could not change hierarchy for %s: 0x%x", desc, rval);
    }

    return rval;
}

static int take_ownership(TSS2_SYS_CONTEXT* sys, TPM2B_AUTH* newSecretKey, TPM2B_AUTH* oldSecretKey)
{
    TSS2_RC rc;

    rc = change_auth(sys, newSecretKey, oldSecretKey, "Owner", TPM2_RH_OWNER);
    if(rc != TPM2_RC_SUCCESS)
    {
        return rc;
    }

    rc = change_auth(sys, newSecretKey, oldSecretKey, "Endorsement", TPM2_RH_ENDORSEMENT);
    if(rc != TPM2_RC_SUCCESS)
    {
        return rc;
    }

    rc = change_auth(sys, newSecretKey, oldSecretKey, "Lockout", TPM2_RH_LOCKOUT);
    if(rc != TPM2_RC_SUCCESS)
    {
        return rc;
    }

    return rc;
}


//-------------------------------------------------------------------------------------------------
// C R E A T E   P R I M A R Y
// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_createprimary.c
//-------------------------------------------------------------------------------------------------
static int create_primary(TSS2_SYS_CONTEXT *sys, TPM2B_AUTH* newSecretKey, TPM2_HANDLE* handle2048rsa) {

    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_COMMAND  sessionsData = {0};
    TPM2B_SENSITIVE_CREATE  inSensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT;
    TPM2B_PUBLIC            inPublic = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
 
    sessionsData.count = 1;
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    memcpy(&sessionsData.auths[0].hmac, newSecretKey, sizeof(TPM2B_AUTH));
    sessionsData.auths[0].sessionAttributes = 0;

    //memcpy(&inSensitive.sensitive.userAuth, newSecretKey, sizeof(TPM2B_AUTH));
    inSensitive.size = inSensitive.sensitive.userAuth.size + sizeof(inSensitive.size);

    inPublic.publicArea.type = TPM2_ALG_RSA;           // -G 0x0001
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;     // -g 0x000B
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    creationPCR.count = 0;

    rval = Tss2_Sys_CreatePrimary(sys, TPM2_RH_OWNER, &sessionsData,
                                  &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                                  handle2048rsa, &outPublic, &creationData, &creationHash,
                                  &creationTicket, &name, &sessionsDataOut);

    if(rval == TPM2_RC_SUCCESS) 
    {
        DEBUG("Create primary was successfull")
    }
    else
    {
        ERROR("Tss2_Sys_CreatePrimary Failed: 0x%0x\n", rval);
    }

    return rval;
}

//-------------------------------------------------------------------------------------------------
// 'TakeOwnership' wraps three tpm2-tools commands: tpm2_takeownership, tpm2_createprimary 
// and tpm2_evictcontrol
//-------------------------------------------------------------------------------------------------
int TakeOwnership(tpmCtx* ctx, char* secretKey, size_t keyLen) 
{
    TSS2_RC rval = 0;
    TPM2_HANDLE handle2048rsa = 0;
    TPM2B_AUTH newSecretKey = {0};
    TPM2B_AUTH oldSecretKey = {0};      // KWT: 9/10/2019 email to Tim/Haidong re: change password use case

    if(secretKey == NULL)
    {
        ERROR("The TPM secret key must be provided.")
        return -1;
    }

    if(keyLen == 0 || keyLen > sizeof(TPM2B_AUTH))
    {
        ERROR("Invalid secret key length.")
        return -2;
    }

    memcpy(&newSecretKey.buffer, secretKey, keyLen);
    newSecretKey.size = keyLen;

    // Is there a use case for changing the secret key?  I don't see it java
    //
    // KWT:  creating two secret keys so that in the future we can takeownership
    // with an 'old password'
    //   memcpy(&oldSecretKey.buffer, secretKey, keyLen);
    //   oldSecretKey.size = keyLen;
    //
    // https://github.com/tpm2-software/tpm2-tss/issues/233 (see Jul8, 2016 comment)
    // if(!clear_hierarchy_auth(ctx->sys, &oldSecretKey))
    // {
    //     return -1;        
    // }


    //
    // TakeOwnership of 'owner', 'endorsement' and 'lockout' similar to running...
    // tpm2_takeownership -o hex:c758af994ac60743fdf1ad5d8186ca216657f99f -e hex:c758af994ac60743fdf1ad5d8186ca216657f99f -l hex:c758af994ac60743fdf1ad5d8186ca216657f99f
    //
    rval = take_ownership(ctx->sys, &newSecretKey, &oldSecretKey);
    if(rval != TPM2_RC_SUCCESS)
    {
        return rval;
    }

    // 
    // CreatePrimary, with the output in 'handle2048rsa', similar to tpm2-tool command...
    // tpm2_createprimary -H o -P hex:c758af994ac60743fdf1ad5d8186ca216657f99f -g 0x000B -G 0x0001 -C /tmp/primaryKey.context
    // 
    rval = create_primary(ctx->sys, &newSecretKey, &handle2048rsa);
    if(rval != TPM2_RC_SUCCESS)
    {
        return rval;
    }

    //
    // Use EvitControl to save the output from CreatePrimary to nvram similar to...
    // tpm2_evictcontrol -A o -P hex:c758af994ac60743fdf1ad5d8186ca216657f99f -c /tmp/primaryKey.context -S 0x81000000
    //
    rval = evict_control(ctx->sys, &newSecretKey, handle2048rsa);
    if(rval != TPM2_RC_SUCCESS)
    {
        return rval;
    }

    return TPM2_RC_SUCCESS;
}

//
// This function operates similar to the TpmLinuxV20.java implementation:  if 'change_auth' is successfull 
// when applying the same password for new/old keys, then consider the TPM owned with password 'secretKey'.
// 
// Returns zero (true) if the secretKey works against the TPM. Any other value is error
// returns 0 if true (owned) 
// all other values are false (error codes)
//  false
int IsOwnedWithAuth(tpmCtx* ctx, char* secretKey, size_t keyLen)
{
    if(secretKey == NULL)
    {
        ERROR("The TPM secret key must be provided.")
        return -1;
    }

    if(keyLen == 0 || keyLen > sizeof(TPM2B_AUTH))
    {
        ERROR("Invalid secret key length.")
        return -2;
    }

    TPM2B_AUTH newSecretKey = {0};
    memcpy(&newSecretKey.buffer, secretKey, keyLen);
    newSecretKey.size = keyLen;

    return take_ownership(ctx->sys, &newSecretKey, &newSecretKey);
}