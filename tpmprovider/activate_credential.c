/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"


// https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_activatecredential.c
int Tss2ActivateCredential(TSS2_SYS_CONTEXT* sys, TPMS_AUTH_COMMAND* endorsePassword, TPMS_AUTH_COMMAND* aikPassword, TPM2B_ID_OBJECT* credentialBlob, TPM2B_ENCRYPTED_SECRET* secret, TPM2B_DIGEST* certInfoData)
{
    TSS2_RC rval;
//    TPM2B_DIGEST certInfoData = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    TSS2L_SYS_AUTH_COMMAND cmd_auth_array_password = {0};
    cmd_auth_array_password.count = 2;
    memcpy(&cmd_auth_array_password.auths[0], aikPassword, sizeof(TPMS_AUTH_COMMAND));

    TSS2L_SYS_AUTH_COMMAND cmd_auth_array_endorse = {0};
    cmd_auth_array_endorse.count = 1;
    memcpy(&cmd_auth_array_endorse.auths[0], endorsePassword, sizeof(TPMS_AUTH_COMMAND));

    TPMI_DH_OBJECT tpmKey = TPM2_RH_NULL;
    TPMI_DH_ENTITY bind = TPM2_RH_NULL;
    TPM2B_NONCE nonceNewer = TPM2B_EMPTY_INIT;
    nonceNewer.size = TPM2_SHA1_DIGEST_SIZE;                    // ???
    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;
    nonceCaller.size = TPM2_SHA1_DIGEST_SIZE;                   // ???
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER salt = {0};
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL
    };
    TPMI_SH_POLICY sessionHandle; 
    
    rval = Tss2_Sys_StartAuthSession(sys, tpmKey, bind, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &sessionHandle, &nonceNewer, 0);
    if( rval != TPM2_RC_SUCCESS )
    {
        ERROR("Tss2_Sys_StartAuthSession Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_PolicySecret(sys, TPM2_RH_ENDORSEMENT, sessionHandle, &cmd_auth_array_endorse, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return rval;
    }

    cmd_auth_array_password.auths[1].sessionHandle = sessionHandle;
    cmd_auth_array_password.auths[1].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    cmd_auth_array_password.auths[1].hmac.size = 0;

    rval = Tss2_Sys_ActivateCredential(sys, TPM_HANDLE_AIK, TPM_HANDLE_EK_CERT, &cmd_auth_array_password, credentialBlob, secret, certInfoData, 0);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("Tss2_Sys_ActivateCredential failed. TPM Error:0x%x", rval);
        return rval;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(sys, sessionHandle);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return rval;
    }
 
    return TPM2_RC_SUCCESS;    
}


int ActivateCredential(tpmCtx* ctx, 
                       char* tpmSecretKey, 
                       size_t tpmSecretKeyLength,
                       char* aikSecretKey, 
                       size_t aikSecretKeyLength,
                       char* credentialBytes, 
                       size_t credentialBytesLength,
                       char* secretBytes, 
                       size_t secretBytesLength,
                       char **decrypted,
                       int *decryptedLength)
{
    TSS2_RC                 rval;
    TPMS_AUTH_COMMAND       endorsePassword = {0};
    TPMS_AUTH_COMMAND       aikPassword = {0};
    TPM2B_ID_OBJECT         credentialBlob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);
    TPM2B_ENCRYPTED_SECRET  secret = TPM2B_TYPE_INIT(TPM2B_ENCRYPTED_SECRET, secret);
    TPM2B_DIGEST            certInfoData = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    //
    // populate passwords
    //
    str2Tpm2bAuth(tpmSecretKey, tpmSecretKeyLength, &endorsePassword.hmac);
    endorsePassword.sessionHandle = TPM2_RS_PW;

    str2Tpm2bAuth(aikSecretKey, aikSecretKeyLength, &aikPassword.hmac);
    aikPassword.sessionHandle = TPM2_RS_PW;

    //
    // copy credentialBytes into the TPM2B_ID_OBJECT
    //
    if(credentialBytes == NULL || credentialBytesLength == 0 || credentialBytesLength > ARRAY_SIZE(credentialBlob.credential))
    {
        ERROR("Invalid credential bytes");
        return -1;
    }

    credentialBlob.size = credentialBytesLength;
    memcpy(credentialBlob.credential, credentialBytes, credentialBytesLength);

    //
    // copy secretBytes into the TPM2B_ENCRYPTED_SECRET
    //
    if(secretBytes == NULL || secretBytesLength == 0 || secretBytesLength > ARRAY_SIZE(secret.secret))
    {
        ERROR("Invalid secret bytes");
        return -1;
    }

    secret.size = secretBytesLength;
    memcpy(secret.secret, secretBytes, secretBytesLength);

    //
    // Now call activate credential
    //
    rval = Tss2ActivateCredential(ctx->sys, &endorsePassword, &aikPassword, &credentialBlob, &secret, &certInfoData);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (certInfoData.size == 0)
    {
        ERROR("No data was returned from ActivateCredentail");
        return -1;
    }

    // this will be freed by cgo in tpmlinx20.go
    *decrypted = (char*)calloc(certInfoData.size, 1);
    if (!*decrypted)
    {
        ERROR("Could not allocated decrypted buffer");
        return -1;
    }

    memcpy(*decrypted, certInfoData.buffer, certInfoData.size);
    *decryptedLength = certInfoData.size;

    return 0;
}

// // From https://raw.githubusercontent.com/tpm2-software/tpm2-tools/3.1.0/tools/tpm2_makecredential.c
// static int MakeCredential(TSS2_SYS_CONTEXT* sys, TPM2B_DIGEST* credential, TPM2B_NAME* aikName, TPM2B_ENCRYPTED_SECRET* secret, TPM2B_ID_OBJECT* credentialBlob)
// {
//     TSS2_RC                 rval;
//     TSS2L_SYS_AUTH_RESPONSE sessionDataOut;
//     TPM2B_NAME              name_ext = TPM2B_TYPE_INIT(TPM2B_NAME, name);
//     TPM2B_PUBLIC            ekPublic = {0};
//     TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
//     TPM2_HANDLE             rsa2048_handle;
//     TPM2B_NAME              qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

//     rval = Tss2_Sys_ReadPublic(sys, TPM_HANDLE_EK_CERT, 0, &ekPublic, &name, &qualifiedName, &sessionDataOut);
//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("Tss2_Sys_ReadPublic failed. TPM Error:0x%x", rval);
//         return rval;
//     }

//     rval = Tss2_Sys_LoadExternal(sys, 0, NULL, &ekPublic, TPM2_RH_NULL, &rsa2048_handle, &name_ext, &sessionDataOut);
//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("LoadExternal failed. TPM Error:0x%x", rval);
//         return rval;
//     }

//     rval = Tss2_Sys_MakeCredential(sys, rsa2048_handle, 0, credential, aikName, credentialBlob, secret, &sessionDataOut);
//     if (rval != TPM2_RC_SUCCESS) 
//     {
//         ERROR("MakeCredential failed. TPM Error:0x%x", rval);
//         return rval;
//     }

//     rval = Tss2_Sys_FlushContext(sys, rsa2048_handle);
//     if (rval != TPM2_RC_SUCCESS) {
//         ERROR("Flush loaded key failed. TPM Error:0x%x", rval);
//         return rval;
//     }

//     return TPM2_RC_SUCCESS; 
// }


// int ActivateIdentity(tpmCtx* ctx, 
//                      char* tpmSecretKey, 
//                      size_t tpmSecretKeyLength,
//                      char* aikSecretKey, 
//                      size_t aikSecretKeyLength,
//                      char* aikNameBytes, 
//                      size_t aikNameBytesLength,
//                      char* nonce, 
//                      size_t nonceLength,
//                      char **decrypted,
//                      int *decryptedLength)
// {
//     // TSS2_RC rval;

//     // TPM2B_DIGEST            credential;
//     // TPM2B_NAME              aikName = TPM2B_EMPTY_INIT;
//     // TPM2B_ENCRYPTED_SECRET  secret = TPM2B_TYPE_INIT(TPM2B_ENCRYPTED_SECRET, secret);
//     // TPM2B_ID_OBJECT         credentialBlob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);
//     // TPMS_AUTH_COMMAND       aikPassword = {0};
//     // TPMS_AUTH_COMMAND       endorsePassword = {0};

//     // str2Tpm2bAuth(tpmSecretKey, tpmSecretKeyLength, &endorsePassword.hmac);
//     // str2Tpm2bAuth(aikSecretKey, aikSecretKeyLength, &aikPassword.hmac);

//     // endorsePassword.sessionHandle = TPM2_RS_PW;
//     // aikPassword.sessionHandle = TPM2_RS_PW;

//     // if(aikNameBytes == NULL || aikNameBytesLength == 0 || aikNameBytesLength > ARRAY_SIZE(aikName.name))
//     // {
//     //     ERROR("Invalid aik name");
//     //     return -1;
//     // }

//     // aikName.size = aikNameBytesLength;
//     // memcpy(aikName.name, aikNameBytes, aikNameBytesLength);

//     // if (nonce == NULL || nonceLength == 0 || nonceLength > ARRAY_SIZE(credential.buffer))
//     // {
//     //     ERROR("Invalid nonce");
//     //     return -1;
//     // }

//     // credential.size = nonceLength;
//     // memcpy(credential.buffer, nonce, nonceLength);

//     // rval = MakeCredential(ctx->sys, &credential, &aikName, &secret, &credentialBlob);
//     // if (rval != TSS2_RC_SUCCESS)
//     // {
//     //     return rval;
//     // }

//     // rval = ActivateCredential(ctx->sys, &endorsePassword, &aikPassword, &credentialBlob, &secret);
//     // if (rval != TSS2_RC_SUCCESS)
//     // {
//     //     return rval;
//     // }

//     // DEBUG("OK");

//     return 0;
// }