
/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

// // https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_util.c
// // Move this to util and share with str2tmp2bauth
// static int tpm2_util_hex_to_byte_structure(const char *inStr, UINT16 *byteLength, BYTE *byteBuffer) 
// {
//     int strLength; //if the inStr likes "1a2b...", no prefix "0x"
//     int i = 0;
//     if (inStr == NULL || byteLength == NULL || byteBuffer == NULL)
//         return -1;
//     strLength = strlen(inStr);
//     if (strLength % 2)
//         return -2;
//     for (i = 0; i < strLength; i++) {
//         if (!isxdigit(inStr[i]))
//             return -3;
//     }

//     if (*byteLength < strLength / 2)
//         return -4;

//     *byteLength = strLength / 2;

//     for (i = 0; i < *byteLength; i++) {
//         char tmpStr[4] = { 0 };
//         tmpStr[0] = inStr[i * 2];
//         tmpStr[1] = inStr[i * 2 + 1];
//         byteBuffer[i] = strtol(tmpStr, NULL, 16);
//     }
//     return 0;
// }

// static int pcr_parse_selection(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel) 
// {
//     const char *strLeft;
//     char buf[7];

//     if (str == NULL || len == 0 || strlen(str) == 0)
//         return FALSE;

//     strLeft = memchr(str, ':', len);

//     if (strLeft == NULL) {
//         return FALSE;
//     }

//     if ((size_t)(strLeft - str) > sizeof(buf) - 1) {
//         return FALSE;
//     }

//     snprintf(buf, strLeft - str + 1, "%s", str);

//     pcrSel->hash = tpm2_alg_util_from_optarg(buf);

//     if (pcrSel->hash == TPM2_ALG_ERROR) {
//         return FALSE;
//     }

//     strLeft++;

//     if ((size_t)(strLeft - str) >= len) {
//         return FALSE;
//     }

//     if (!pcr_parse_list(strLeft, str + len - strLeft, pcrSel)) {
//         return FALSE;
//     }

//     return TRUE;
// }

// //
// // https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/pcr.c
// //
// // 0x04:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23+0x0B:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
// //
// static int pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels) 
// {
//     const char *strLeft = arg;
//     const char *strCurrent = arg;
//     int lenCurrent = 0;

//     if (arg == NULL || pcrSels == NULL) {
//         return FALSE;
//     }

//     pcrSels->count = 0;

//     do {
//         strCurrent = strLeft;

//         strLeft = strchr(strCurrent, '+');
//         if (strLeft) 
//         {
//             lenCurrent = strLeft - strCurrent;
//             strLeft++;
//         } 
//         else
//         {
//             lenCurrent = strlen(strCurrent);
//         }

//         if (!pcr_parse_selection(strCurrent, lenCurrent, &pcrSels->pcrSelections[pcrSels->count]))
//         {
//             return FALSE;
//         }

//         pcrSels->count++;
//     } while (strLeft);

//     if (pcrSels->count == 0) {
//         return FALSE;
//     }

//     return TRUE;
// }

// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_quote.c
static int getQuote(TSS2_SYS_CONTEXT* sys, 
                 TPM2B_AUTH* akPassword,
                 TPM2_HANDLE akHandle, 
                 TPML_PCR_SELECTION *pcrSelection, 
                 TPM2B_DATA* qualifyingData, 
                 TPM2B_ATTEST* quote, 
                 TPMT_SIGNATURE* signature)
{
    TSS2_RC rval;
    TPMT_SIG_SCHEME inScheme;
    TSS2L_SYS_AUTH_COMMAND sessionsData = { 1, {{.sessionHandle=TPM2_RS_PW}}};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    // TPM2B_ATTEST quoted = TPM2B_TYPE_INIT(TPM2B_ATTEST, attestationData);
    // TPMT_SIGNATURE signature;

    inScheme.scheme = TPM2_ALG_NULL;

    memcpy(&sessionsData.auths[0].hmac, akPassword, sizeof(TPM2B_AUTH));

    memset( (void *)signature, 0, sizeof(TPMT_SIGNATURE) );

    rval = Tss2_Sys_Quote(sys, akHandle, &sessionsData,
            qualifyingData, &inScheme, pcrSelection, quote,
            signature, &sessionsDataOut);

    if(rval != TPM2_RC_SUCCESS)
    {
        ERROR("Quote Failed ! ErrorCode: 0x%0x", rval);
        return rval;
    }

    // tpm2_tool_output( "\nquoted:\n " );
    // tpm2_util_print_tpm2b( (TPM2B *)&quoted );
    // //PrintTPM2B_ATTEST(&quoted);
    // tpm2_tool_output( "\nsignature:\n " );
    // PrintBuffer( (UINT8 *)&signature, sizeof(signature) );
    // //PrintTPMT_SIGNATURE(&signature);

    // bool res = write_output_files(&quoted, &signature);
    // return res == true ? 0 : 1;

    return TSS2_RC_SUCCESS;
}

int GetTpmQuote(tpmCtx* ctx, 
                char* aikSecretKey, 
                size_t aikSecretKeyLength, 
                // char* pcrSelectionString,
                // size_t pcrSelectionStringLength,
                // char* qualifyingDataString,
                // size_t qualifyingDataStringLength
                char** quoteBytes, 
                int* quoteBytesLength)
{
    TSS2_RC             rval;
    TPM2B_AUTH          aikPassword = {0};
    TPM2B_ATTEST        quote = {0}; 
    TPMT_SIGNATURE      signature = {0};
    TPML_PCR_SELECTION  pcrSelection = {0};
    TPM2B_DATA          qualifyingData;

    rval = str2Tpm2bAuth(aikSecretKey, aikSecretKeyLength, &aikPassword);
    if(rval != 0)
    {
        ERROR("There was an error creating the aik TPM2B_AUTH");
        return rval;
    }

    // if (pcrSelectionString == NULL || pcrSelectionStringLength == 0 || pcrSelectionStringLength > 140)
    // {
    //     ERROR("Invalid qualifyingDataString parameter");
    //     return -1;
    // }

    // // if(!pcr_parse_selections(pcrSelectionString, &pcrSelection))
    // // {
    // //     ERROR("Could not parse pcr selection string %s", pcrSelectionString)
    // //     return -1;
    // // }

    // if (qualifyingDataString == NULL || qualifyingDataStringLength == 0 || qualifyingDataStringLength > ARRAY_SIZE(qualifyingData.buffer))
    // {
    //     ERROR("Invalid qualifyingDataString parameter");
    //     return -1;
    // }

    pcrSelection.count = 2;
    pcrSelection.pcrSelections[0].hash = 0x04;
    pcrSelection.pcrSelections[0].sizeofSelect = 3;
    pcrSelection.pcrSelections[0].pcrSelect[0] = 0xff;
    pcrSelection.pcrSelections[0].pcrSelect[1] = 0xff;
    pcrSelection.pcrSelections[0].pcrSelect[2] = 0xff;

    pcrSelection.pcrSelections[1].hash = 0x0b;
    pcrSelection.pcrSelections[1].sizeofSelect = 3;
    pcrSelection.pcrSelections[1].pcrSelect[0] = 0xff;
    pcrSelection.pcrSelections[1].pcrSelect[1] = 0xff;
    pcrSelection.pcrSelections[1].pcrSelect[2] = 0xff;


    qualifyingData.size = sizeof(qualifyingData) - 2;     // less two is for uint16 size --> using what ever is on the stack for now
    // // if(tpm2_util_hex_to_byte_structure(qualifyingDataString, &qualifyingData.size, qualifyingData.buffer) != 0)
    // // {
    // //     ERROR("Could not convert \"%s\" from a hex string to byte array!", qualifyingDataString);
    // //     return -1;
    // }

    rval = getQuote(ctx->sys, 
                 &aikPassword,
                 TPM_HANDLE_AIK, 
                 &pcrSelection, 
                 &qualifyingData, 
                 &quote, 
                 &signature);

    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    // validate size before allocating a new buffer
    if(signature.signature.rsassa.sig.size == 0 || signature.signature.rsassa.sig.size > ARRAY_SIZE(signature.signature.rsassa.sig.buffer)) 
    {
         ERROR("Incorrect signature buffer size: x", signature.signature.rsassa.sig.size)
         return -1;   
    }

    if(quote.size == 0 || quote.size > ARRAY_SIZE(quote.attestationData)) 
    {
         ERROR("Incorrect quote buffer size: x", quote.size)
         return -1;   
    }

    // TpmV20.java uses https://github.com/microsoft/TSS.MSR/blob/master/TSS.Java/src/tss/tpm/QuoteResponse.java
    // buffer returned to hvs needs to be...
    // 4 bytes: int size of quote
    // n bytes: quote buf
    // 4 bytes: int size of signature
    // n bytes: signature buf
    // (base64 encoded in go)
    size_t bufferSize = sizeof(uint32_t) + quote.size + sizeof(uint32_t) + signature.signature.rsassa.sig.size;
    *quoteBytes = calloc(bufferSize, 1);
    if(!*quoteBytes) 
    {
        ERROR("Could not allocate quote buffer");
        return -1;
    }

    size_t off = 0;
    memcpy((*quoteBytes + off), &quote.size, sizeof(uint32_t));
    off += sizeof(uint32_t);

    memcpy((*quoteBytes + off), &quote.attestationData, quote.size);
    off += quote.size;

    memcpy((*quoteBytes + off), &signature.signature.rsassa.sig.size, sizeof(uint32_t));
    off += sizeof(uint32_t);

    memcpy((*quoteBytes + off), &signature.signature.rsassa.sig.buffer, signature.signature.rsassa.sig.size);
    off += sizeof(uint32_t);

    *quoteBytesLength = bufferSize;
    return TSS2_RC_SUCCESS;
}