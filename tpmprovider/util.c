#include "tpm20linux.h"

// Utility function that takes an ascii string and converts it into a TPM2B_AUTH similar
// to https://raw.githubusercontent.com/tpm2-software/tpm2-tools/3.1.0/lib/tpm2_util.c
// (tpm2_util_hex_to_byte_structure).
int str2Tpm2bAuth(const char* tpmSecretKey, size_t keyLength, TPM2B_AUTH* tpm2bAuth) 
{
    int i = 0;

    if(tpmSecretKey == NULL)
    {
        ERROR("The TPM secret key must be provided.")
        return -1;
    }

    if(keyLength == 0 || keyLength > ARRAY_SIZE(tpm2bAuth->buffer))
    {
        ERROR("Invalid secret key length.")
        return -2;
    }

//    DEBUG("SK: '%s'", tpmSecretKey);

    if (tpm2bAuth == NULL)
    {
        ERROR("TPM2B_AUTH was not provided");
        return -3;
    }

    if (keyLength % 2)
    {
        ERROR("The tpm key must be even in length");
        return -4;
    }

    if (keyLength/2 > ARRAY_SIZE(tpm2bAuth->buffer))
    {
        ERROR("Invalid key length");
        return -5;
    }

    tpm2bAuth->size = keyLength/2;

    for (i = 0; i < tpm2bAuth->size; i++) 
    {
        char tmpStr[4] = { 0 };
        tmpStr[0] = tpmSecretKey[i * 2];
        tmpStr[1] = tpmSecretKey[i * 2 + 1];
        tpm2bAuth->buffer[i] = strtol(tmpStr, NULL, 16);
    }

    return 0;
}


//
// Returns 0 if true, -1 for false, all other values are error codes
//
// KWT:  NEEDED?
int NvIndexExists(tpmCtx* ctx, uint32_t nvIndex)
{
    TSS2_RC rval;
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TPM2B_NAME nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_NV_ReadPublic(ctx->sys, nvIndex, NULL, &nv_public, &nv_name, NULL);
    DEBUG("Tss2_Sys_NV_ReadPublic rval = 0x%0x", rval);
    if(rval == 0x184)
    {
        return -1;
    }
    
    return rval;
}

// KWT:  NEEDED?
int PublicKeyExists(tpmCtx* ctx, uint32_t handle)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPM2B_PUBLIC            inPublic = TPM2B_EMPTY_INIT;;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME              qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, 0, &inPublic, &name, &qualified_name, &sessionsDataOut);
    DEBUG("Tss2_Sys_ReadPublic handle 0x%x returned 0x%0x", handle, rval);
    // if (rval != TPM2_RC_SUCCESS) 
    // {
    //     ERROR("TPM2_ReadPublic error: rval = 0x%0x", rval);
    //     return rval;
    // }

    return rval;

}

// https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_nv_util.h::tpm2_util_nv_max_buffer_size
int GetMaxNVBufferSize(TSS2_SYS_CONTEXT *sys, uint32_t *size) 
{
    TSS2_RC rval;
    TPMS_CAPABILITY_DATA cap_data;
    TPMI_YES_NO more_data;

    if(!sys)
    {
        ERROR("TSS2_SYS_CONTEXT was not provided.");
    }

    if(!size)
    {
        ERROR("'size' was not provided.")
    }

    *size = 0;

    rval = Tss2_Sys_GetCapability (sys, NULL, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, &more_data, &cap_data, NULL);
    
    if (rval != TSS2_RC_SUCCESS) 
    {
        ERROR("Failed to query max transmission size via Tss2_Sys_GetCapability. Error:0x%x", rval);
    } 
    else
    {
        *size = cap_data.data.tpmProperties.tpmProperty[0].value;
    }

    return rval;
}


int ReadPublic(tpmCtx* ctx, uint32_t handle, char **public, int *publicLength)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPM2B_PUBLIC            inPublic = TPM2B_EMPTY_INIT;;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME              qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, 0, &inPublic, &name, &qualified_name, &sessionsDataOut);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if(inPublic.publicArea.unique.rsa.size == 0 || inPublic.publicArea.unique.rsa.size > ARRAY_SIZE(inPublic.publicArea.unique.rsa.buffer))
    {
        ERROR("ReadPublic:  Invalid buffer size");
        return -1;
    }

    // this will be freed by cgo in tpmlinx20.go
    *public = (char*)calloc(inPublic.publicArea.unique.rsa.size, 1);
    if (!*public)
    {
        ERROR("ReadPublic: Could not allocated buffer");
        return -1;
    }

    memcpy(*public, inPublic.publicArea.unique.rsa.buffer, inPublic.publicArea.unique.rsa.size);
    *publicLength = inPublic.publicArea.unique.rsa.size;

    return 0;
}