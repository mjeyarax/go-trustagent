// yum install tpm2-abrmd-devel.x86_64
// SDL linking securirty issues

#include <stdlib.h>
#include <stdio.h> // remove (printf?)
#include <string.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2-tcti-tabrmd.h>

#include "tpm.h"

// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_util.h
#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define TPMT_TK_CREATION_EMPTY_INIT { \
        .tag = 0, \
		.hierarchy = 0, \
		.digest = TPM2B_EMPTY_INIT \
    }

#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data.size = 0, \
                .userAuth.size = 0, \
            }, \
    }


#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .type = TPM2_ALG_RSA, \
        .objectAttributes = \
            TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
            |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
            |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH \
        , \
    }, \
}    

struct tpm
{
    TPM_VERSION version;
    TSS2_TCTI_CONTEXT* tcti;
    TSS2_SYS_CONTEXT* sys;
};

tpm* TpmCreate()
{
    tpm* t = NULL;
    size_t size = 0;
    TSS2_RC rc = 0;
    TSS2_ABI_VERSION abiVersion = {0};

    t = (tpm*)calloc(1, sizeof(tpm));  // todo: error check
    t->version = TPM_VERSION_LINUX_20;

    rc = Tss2_Tcti_Tabrmd_Init(NULL, &size, NULL);
    t->tcti = (TSS2_TCTI_CONTEXT*)calloc(1, size);
    rc = Tss2_Tcti_Tabrmd_Init(t->tcti, &size, NULL);

    abiVersion.tssCreator = 1;
    abiVersion.tssFamily = 2;
    abiVersion.tssLevel = 1;
    abiVersion.tssVersion = 108;

    size = Tss2_Sys_GetContextSize(0);
    t->sys = (TSS2_SYS_CONTEXT*)calloc(1, size);
    rc = Tss2_Sys_Initialize(t->sys, size, t->tcti, &abiVersion);

    return t;
}

void TpmDelete(tpm* tpm)
{
    if(tpm != NULL)
    {
        if(tpm->sys)
        {
            Tss2_Sys_Finalize(tpm->sys);
            free(tpm->sys);
        }

        if(tpm->tcti)
        {
            Tss2_Tcti_Finalize(tpm->tcti);
            free(tpm->tcti);
        }

        free(tpm);
    }
}

TPM_VERSION Version(tpm* tpm)
{
    return tpm->version;
}

// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_createprimary.c
static int create_primary(TSS2_SYS_CONTEXT *sapi_context, char* ownerAuth, int len) {

    UINT32 rval;

    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {0};
    inSensitive.size = sizeof(inSensitive) + len;
    inSensitive.sensitive.userAuth.size = len;
    memcpy(inSensitive.sensitive.userAuth.buffer, ownerAuth, len);



    TPM2B_PUBLIC in_public = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT;
    TPMI_ALG_HASH nameAlg = TPM2_ALG_SHA256;
    TPM2_HANDLE handle2048rsa;  // THIS IS A HANDLE TO A CERT THAT NEEDS TO BE SAVED?


    TSS2L_SYS_AUTH_COMMAND sessionsData;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;

    sessionsData.count = 1;
    sessionsData.auths[0] = session_data;
    

    creationPCR.count = 0;

    rval = Tss2_Sys_CreatePrimary(sapi_context, TPM2_RH_OWNER, &sessionsData,
                                  &inSensitive, &in_public, &outsideInfo, &creationPCR,
                                  &handle2048rsa, &outPublic, &creationData, &creationHash,
                                  &creationTicket, &name, &sessionsDataOut);

    if(rval != TPM2_RC_SUCCESS) {
        printf("CreatePrimary Failed ! ErrorCode: 0x%0x\n", rval);
        return -2;
    }

    return 0;
}



// static int create_primary(TSS2_SYS_CONTEXT *sapiCtx, unsigned int ownerAuthLen, const unsigned char* ownerAuth, TPM2_HANDLE* objectHandle /* out */, unsigned int authHandle) {
//     TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT;

//     TSS2L_SYS_AUTH_COMMAND sessionsData = {
//         .count = 1, .auths = {{
//             .sessionHandle = TPM2_RS_PW,
//             .hmac = {
//                 .size = 0
//             },
//             .nonce = {
//                 .size = ownerAuthLen
//             }
//         }}
//     };

//     memcpy(sessionsData.auths[0].nonce.buffer, ownerAuth, ownerAuthLen);
//     TPM2B_PUBLIC inPublic = {
//         .size = sizeof(TPM2_ALG_ID) + sizeof(TPM2_ALG_ID) + sizeof(TPMA_OBJECT) + sizeof(UINT16)
//                         + sizeof(TPM2_ALG_ID) + sizeof(TPMU_SYM_KEY_BITS) + sizeof(TPMI_ALG_SYM_MODE)
//                         + sizeof(TPMI_ALG_RSA_SCHEME) + sizeof(TPMI_RSA_KEY_BITS) + sizeof(UINT32)
//                         + sizeof(UINT16),
//         .publicArea = {
//             .type = TPM2_ALG_RSA,
//             .nameAlg = TPM2_ALG_SHA256,
//             .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN,
//             .authPolicy = {
//                 .size = 0,
//             },
//             .parameters = {
//                 .rsaDetail = {
//                     .symmetric = {
//                         .algorithm = TPM2_ALG_AES,
//                         .keyBits = 128,
//                         .mode = {
//                             .sym = TPM2_ALG_CFB
//                         }
//                     },
//                     .scheme = {
//                         .scheme = TPM2_ALG_NULL
//                     },
//                     .keyBits = 2048,
//                     .exponent = 0
//                 }
//             },
//             .unique = {
//                 .rsa = {
//                     .size = 0
//                 }
//             }
//         }
//     };
//     TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
//     TPML_PCR_SELECTION creationPCR;
//     TPM2B_PUBLIC outPublic = TPM2B_EMPTY_INIT;
//     TPM2B_CREATION_DATA creationData = TPM2B_EMPTY_INIT;
//     TPM2B_DIGEST creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
//     TPMT_TK_CREATION creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
//     TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
//     TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

//     printf("(in create primary) or maybe that's the pointer...: 0x%X", *objectHandle);

//     TSS2_RC rc = Tss2_Sys_CreatePrimary(sapiCtx, TPM2_RH_OWNER, &sessionsData, &inSensitive, &inPublic, &outsideInfo, 
//                                 &creationPCR, objectHandle, &outPublic, &creationData, &creationHash, 
//                                 &creationTicket, &name, &sessionsDataOut);
//     return rc;
// }











int TakeOwnership(tpm* tpm, char* secretKey, int len)
{
    if(secretKey == NULL)
    {
        return -1;
    }

    if(len > 20)
    {
        return -2;
    }

    printf("TakeOwnership size %d\n", len);
    return 0;
}

// returns 0 if true, 
// negative -> error
// 1 false
int IsOwnedWithAuth(tpm* tpm, char* secretKey, int len)
{
    if(secretKey == NULL)
    {
        return -1;
    }

    if(len > 20)
    {
        return -2;
    }

    printf("IsOwnedWithAuth size %d\n", len);
    return 0;
}