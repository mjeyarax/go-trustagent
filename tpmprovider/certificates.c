/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

// RENAME THIS FILE TO get_endorsement_key.c

// This code is working, but not currently called by go.  It attempts to replicate...
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
//
// From: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_getpubek.c
// int CreateEndorsementKey(const tpmCtx* ctx, const char* tpmSecretKey, size_t keyLength)
// {
//     TSS2_RC                 rval;
//     TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
//     TSS2L_SYS_AUTH_COMMAND  sessionsData = {0};
//     TPML_PCR_SELECTION      creationPCR;
//     TPM2B_SENSITIVE_CREATE  inSensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT;
//     TPM2B_PUBLIC            inPublic = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT;
//     TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
//     TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
//     TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
//     TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
//     TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
//     TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
//     TPM2_HANDLE             handle2048ek;
//     TPM2_HANDLE             persistentHandle = NV_IDX_ENDORSEMENT_KEY;
//     TPM2B_AUTH              secretKey = {0};

//     rval = str2Tpm2bAuth(tpmSecretKey, keyLength, &secretKey);
//     if (rval != 0) 
//     {
//         return rval;
//     }

// // KWT:  Refactor similar to GetEndorsementCertificate?
//     sessionsData.count = 1;
//     sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
//     memcpy(&sessionsData.auths[0].hmac, &secretKey, sizeof(TPM2B_AUTH));
//     sessionsData.auths[0].sessionAttributes = 0;

//     inSensitive.size = inSensitive.sensitive.userAuth.size + sizeof(inSensitive.size);

//     inPublic.publicArea.type = TPM2_ALG_RSA;           // -G 0x0001
//     inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;     // -g 0x000B
//     inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
//     inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
//     inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
//     inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
//     inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
//     inPublic.publicArea.parameters.rsaDetail.exponent = 0;
//     inPublic.publicArea.unique.rsa.size = 0;

//     creationPCR.count = 0;

//     rval = Tss2_Sys_CreatePrimary(ctx->sys, TPM2_RH_ENDORSEMENT,
//             &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
//             &handle2048ek, &outPublic, &creationData, &creationHash,
//             &creationTicket, &name, &sessionsDataOut);

//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("Tss2_Sys_CreatePrimary Error. TPM Error:0x%x", rval);
//         return rval;
//     }

//     DEBUG("EK create success. Got handle: 0x%8.8x", handle2048ek);

//     memcpy(&sessionsData.auths[0].hmac, &secretKey, sizeof(TPM2B_AUTH));

//     rval = Tss2_Sys_EvictControl(ctx->sys, TPM2_RH_OWNER, handle2048ek,
//             &sessionsData, persistentHandle, &sessionsDataOut);

//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("EvictControl failed. Could not make EK persistent. TPM Error:0x%x", rval);
//         return rval;
//     }

//     DEBUG("EvictControl EK persistent successfull.");

//     rval = Tss2_Sys_FlushContext(ctx->sys, handle2048ek);
//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("Flush transient EK failed. TPM Error:0x%x", rval);
//         return rval;
//     }

//     DEBUG("Flush transient EK successfull.");
//     return rval;
// }

int GetEndorsementKeyCertificate(tpmCtx* ctx, char* tpmSecretKey, size_t keyLength, char** ekCertBytes, int* ekCertBytesLength)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND  sessionsData = {0};
    TPMI_RH_NV_INDEX        nvIndex = NV_IDX_ENDORSEMENT_KEY;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NV_PUBLIC         nvPublic = TPM2B_EMPTY_INIT;
    TPM2B_MAX_NV_BUFFER     nvData = TPM2B_TYPE_INIT(TPM2B_MAX_NV_BUFFER, buffer);
    TPM2B_AUTH              secretKey = {0};                // for tpmSecretKey auth
    uint16_t                certificateBufferSize = 0;      // total size of nv buffer (certificate)
    uint32_t                maxNvBufferSize = 0;            // max nv size that can be read (tpm caps)
    uint16_t                off = 0;                        // offset to read from in nv buffer
    uint16_t                len = 0;                        // size of nv buffer to read

    rval = str2Tpm2bAuth(tpmSecretKey, keyLength, &secretKey);
    if (rval != 0) 
    {
        return rval;
    }
    
    sessionsData.count = 1;
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    memcpy(&sessionsData.auths[0].hmac, &secretKey, sizeof(TPM2B_AUTH));
    sessionsData.auths[0].sessionAttributes = 0;

    // KWT: Working?
    // rval = str2Tpm2bAuth(tpmSecretKey, keyLength, &sessionsData.auths[0].hmac);
    // if (rval != 0) 
    // {
    //     return rval;
    // }

    rval = GetMaxNVBufferSize(ctx->sys, &maxNvBufferSize);
    if (rval != TSS2_RC_SUCCESS) 
    {
        ERROR("GetMaxNVBufferSize returned: 0x%x", rval);
        return rval;
    }

    if(maxNvBufferSize == 0) // KWT check for max
    {
        ERROR("Invalid max nv buffersize returned: 0x%x", maxNvBufferSize);
        return -1;
    }

    // use the Tss2_Sys_NV_ReadPublic to find the total size of the certificate 
    rval = Tss2_Sys_NV_ReadPublic(ctx->sys, nvIndex, NULL, &nvPublic, &name, NULL);
    if (rval != TSS2_RC_SUCCESS) 
    {
        ERROR("Tss2_Sys_NV_ReadPublic returned: 0x%x", rval);
        return rval;
    }

    certificateBufferSize = nvPublic.nvPublic.dataSize;
    if(certificateBufferSize == 0)   // KWT:  check max
    {
        ERROR("Invalid nv buffer size 0x%x", certificateBufferSize);
        return -1;
    }

//    DEBUG("certificate size: 0x%x", certificateBufferSize);

    *ekCertBytesLength = 0;     // return zero in error conditions below
    *ekCertBytes = calloc(certificateBufferSize, 1);
    if(!*ekCertBytes)
    {
        ERROR("Could not allocate endorsement certificate buffer");
        return -1;
    }

    while(off < certificateBufferSize)
    {
        len = certificateBufferSize >  maxNvBufferSize ? maxNvBufferSize : certificateBufferSize;
        if(off + len > certificateBufferSize)
        {
            len = certificateBufferSize - off;
        }

        rval = Tss2_Sys_NV_Read(ctx->sys, TPM2_RH_OWNER, nvIndex, &sessionsData, len, off, &nvData, &sessionsDataOut);
        if (rval != TSS2_RC_SUCCESS) 
        {
            ERROR("Tss2_Sys_NV_Read returned: 0x%x", rval);
            free(*ekCertBytes);
            return rval;
        }

        if (len != nvData.size)
        {
            ERROR("The nvdata size did not match the requested length [len:0x%x, size:0x%x]", len, nvData.size);
            free(*ekCertBytes);
            return rval;
        }

        memcpy(*ekCertBytes + off, nvData.buffer, len);
        off += len;
    }

    *ekCertBytesLength = off;

    return 0;
}

//
// THIS WAS A FAILE ATTEMPT TO GET AN x509 CERT FROM READ_PUBLIC (which is not the correct way to get the 
// endorsement key -- should exist in tpm)
// https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_readpublic.c
// int GetEndorsementKey(tpmCtx* ctx, char* tpmSecretKey, size_t keyLength, char** ekBytes, int* ekBytesLength)
// {
//     TSS2_RC                 rval;
//     TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
//     TPM2B_PUBLIC            inPublic = TPM2B_EMPTY_INIT;
//     TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
//     TPM2B_NAME              qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
//     TPM2_HANDLE             objectHandle = 0x81010000;

//     if(ekBytes == NULL)
//     {
//         ERROR("ekBytes was not provided");
//         return -1;
//     }

//     if(ekBytesLength == NULL)
//     {
//         ERROR("ekBytesLength was not provided");
//         return -1;
//     }

//     rval = Tss2_Sys_ReadPublic(ctx->sys, objectHandle, 0, &inPublic, &name, &qualified_name, &sessionsDataOut);
//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("TPM2_ReadPublic error: rval = 0x%0x", rval);
//         return rval;
//     }

//     if(inPublic.size == 0)
//     {
//         ERROR("The EK does not exist");
//         return -1;
//     }


//     // We're getting a TPM_PUBLIC structure (inPublic) that is a custom tss2 struct.  Translate
//     // it to pem/der bytes similar to...
//     // https://github.com/tpm2-software/tpm2-tools/blob/3.X/scripts/utils/tcgRSApub2PemDer.sh

//     // echo 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' | base64 -d > header.bin
//     char header[] = { 0x30, 0x82, 0x01, 0x22, 0x30, 0x0, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00};
    
//     // echo '02 03' | xxd -r -p >mid-header.bin
//     char mid_header[] = { 0x02, 0x03 };

//     // echo '01 00 01' | xxd -r -p >exponent.bin
//     char exponent[] = { 0x01, 0x00, 0x01 };
 
// //    *ekBytesLength = ARRAY_SIZE(header) + sizeof(TPM2B_PUBLIC_KEY_RSA) + ARRAY_SIZE(mid_header) + ARRAY_SIZE(exponent);
//     *ekBytesLength = ARRAY_SIZE(header) + inPublic.publicArea.unique.rsa.size + ARRAY_SIZE(mid_header) + ARRAY_SIZE(exponent);
//     *ekBytes = calloc(*ekBytesLength, 1);
//     if (*ekBytes == NULL )
//     {
//         ERROR("Could not allocate ek bytes");
//         return -1;
//     }


//     printf("publicArea %x\n", offsetof(TPM2B_PUBLIC, publicArea));
//     printf("unique %x\n", offsetof(TPM2B_PUBLIC, publicArea.unique));
//     printf("rsa %x\n", offsetof(TPM2B_PUBLIC, publicArea.unique.rsa));

//     printf("rsa size %x\n",inPublic.publicArea.unique.rsa.size);


//     size_t off = 0;
    
//     printf("sz:\%xn", ARRAY_SIZE(header));
//     memcpy(*ekBytes + off, &header, ARRAY_SIZE(header));
//     off += ARRAY_SIZE(header);

//     memcpy(*ekBytes + off, &inPublic.publicArea.unique.rsa, inPublic.publicArea.unique.rsa.size);
//     off += inPublic.publicArea.unique.rsa.size;
//     // memcpy(*ekBytes + off, &inPublic.publicArea.unique.rsa, sizeof(TPM2B_PUBLIC_KEY_RSA));
//     // off += sizeof(TPM2B_PUBLIC_KEY_RSA);

//     memcpy(*ekBytes + off, &mid_header, ARRAY_SIZE(mid_header));
//     off += ARRAY_SIZE(mid_header);

//     memcpy(*ekBytes + off, &exponent, ARRAY_SIZE(exponent));
//     off += ARRAY_SIZE(exponent);



//     // rval = Tss2_MU_TPM2B_PUBLIC_Marshal(&inPublic, *ekBytes, sizeof(inPublic), (size_t*)ekBytesLength);
//     // if (rval != TSS2_RC_SUCCESS) 
//     // {
//     //     ERROR("Error serializing outPublic structure: 0x%x", rval);
//     //     return rval; 
//     // } 

//     return rval;
// }