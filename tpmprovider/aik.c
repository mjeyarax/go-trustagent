/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

// return zero if aik is present
// positive is error code from tss2
// -1 is false
int IsAikPresent(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength)
{
    TSS2_RC rval;
    TPM2B_PUBLIC aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &name, &qualifiedName, &sessionsData);
    if (rval != 0)
    {
        return rval;
    }
    else if (aikPublic.size == 0)
    {
        return -1;   // empty results, no aik so false
    }
    
    return 0;   // no error, aikPublic is not empty so true
}


//-------------------------------------------------------------------------------------------------
// tpm2_takeownership -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -l hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
//
// tpm2_createprimary -H o -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -g 0x000B -G 0x0001 -C /tmp/primaryKey.context
//
// tpm2_evictcontrol -A o -P  hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -c /tmp/primaryKey.context -S 0x81000000
//
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
//
// tpm2_readpublic -H 0x81010000 -o /tmp/endorsementkeyecpub
//
// tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beeffeedbeeffeedbeeffeedbeeffeedbeeffeed -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName -g 0x1
// 
//-------------------------------------------------------------------------------------------------
int CreateAik(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength)
{
    // TPML_PCR_SELECTION creation_pcr;
    // TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    // TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {
    //     {
    //     .sessionHandle = TPM2_RS_PW,
    //     .nonce = TPM2B_EMPTY_INIT,
    //     .hmac = TPM2B_EMPTY_INIT,
    //     .sessionAttributes = 0,
    // }}};

    // TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    // TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;
    // TPM2B_NONCE nonce_caller = TPM2B_EMPTY_INIT;
    // TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
    // TPM2B_CREATION_DATA creation_data = TPM2B_EMPTY_INIT;
    // TPM2B_ENCRYPTED_SECRET encrypted_salt = TPM2B_EMPTY_INIT;

    // TPMT_SYM_DEF symmetric = {
    //         .algorithm = TPM2_ALG_NULL,
    // };

    // TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);
    // TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);
    // TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    // TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);
    // TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    // TPM2_HANDLE handle_2048_rsa = ;

    return 0;
}


int GetAikName(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength, char** aikName, int* aikNameLength)
{
    TSS2_RC rval;
    TPM2B_PUBLIC aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &name, &qualifiedName, &sessionsData);
    if(rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (name.size > ARRAY_SIZE(name.name))
    {
        ERROR("Aik name exceeded length %x", ARRAY_SIZE(name.name))
        return -1;
    }

    *aikName = calloc(name.size, 1);
    if(!*aikName)
    {
        ERROR("Could not allocate aik name buffer");
        return -1;
    }

    memcpy(*aikName, name.name, name.size);
    *aikNameLength = name.size;
    
    return 0;
}

int GetAikBytes(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength, char** aikBytes, int* aikBytesLength)
{
    TSS2_RC rval;
    TPM2B_PUBLIC aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME aikName = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &aikName, &qualifiedName, &sessionsData);
    if(rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if( aikPublic.publicArea.unique.rsa.size > ARRAY_SIZE(aikPublic.publicArea.unique.rsa.buffer))
    {
        ERROR("Aik buffer exceeded length %x", ARRAY_SIZE(aikPublic.publicArea.unique.rsa.buffer))
        return -1;   
    }

    *aikBytes = calloc(aikPublic.publicArea.unique.rsa.size, 1);
    if(!*aikBytes)
    {
        ERROR("Could not allocate aik public buffer");
        return -1;
    }

    memcpy(*aikBytes, aikPublic.publicArea.unique.rsa.buffer, aikPublic.publicArea.unique.rsa.size);
    *aikBytesLength = aikPublic.publicArea.unique.rsa.size;
    
    return 0;
}