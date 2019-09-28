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

// from: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_pcrlist.c
static int unset_pcr_sections(TPML_PCR_SELECTION *s) {

    UINT32 i, j;
    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

// from: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_pcrlist.c
static void update_pcr_selections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2) 
{

    UINT32 i1, i2, j;
    for (i2 = 0; i2 < s2->count; i2++) {
        for (i1 = 0; i1 < s1->count; i1++) {
            if (s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for (j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                        ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

// from: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_pcrlist.c
static int getPcrs(TSS2_SYS_CONTEXT* sys, TPML_PCR_SELECTION* requestedPcrs, TPML_DIGEST pcrResults[24], size_t* pcrCount)
{
    TSS2_RC rval;
    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION pcr_selection_out;
    UINT32 pcr_update_counter;
    size_t count = 0;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, requestedPcrs, sizeof(pcr_selection_tmp));

    do {
        DEBUG("PCR COUNT: %d", count);
        rval = Tss2_Sys_PCR_Read(sys, NULL, &pcr_selection_tmp,
                &pcr_update_counter, &pcr_selection_out,
                &pcrResults[count], 0);

        if (rval != TPM2_RC_SUCCESS) 
        {
            ERROR("Tss2_Sys_PCR_Read error: 0x%0x", rval);
            return rval;
        }

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        update_pcr_selections(&pcr_selection_tmp, &pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++count < 24 && !unset_pcr_sections(&pcr_selection_tmp));

    *pcrCount = count;
    return TPM2_RC_SUCCESS;
}


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

    inScheme.scheme = TPM2_ALG_NULL;

    // neded for tpm2-tss-2.0.0-4.el8.x86_64 (rhel8)
    // not needed tpm2-tss-2.1.2-1.fc29.x86_64 (fedora 29)
    memcpy(&sessionsData.auths[0].hmac, akPassword, sizeof(TPM2B_AUTH));

    memset( (void *)signature, 0, sizeof(TPMT_SIGNATURE) );

    rval = Tss2_Sys_Quote(sys, akHandle, &sessionsData,
            qualifyingData, &inScheme, pcrSelection, quote,
            signature, &sessionsDataOut);

    if(rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Quote failed: 0x%0x", rval);
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
                void* pcrSelectionBytes,
                size_t pcrSelectionBytesLength,
                void* qualifyingDataBytes,
                size_t qualifyingDataBytesLength,
                char** quoteBytes, 
                int* quoteBytesLength)
{
    TSS2_RC             rval;
    TPM2B_AUTH          aikPassword = {0};          // KWT: remove
    TPM2B_ATTEST        quote = TPM2B_TYPE_INIT(TPM2B_ATTEST, attestationData);                // quote data from TPM
    TPMT_SIGNATURE      signature = {0};            // signature data from TPM
    TPML_PCR_SELECTION* pcrSelection;               // which banks/pcrs to collect (from HVS request)
    TPM2B_DATA          qualifyingData = {0};       // basically the 'nonce' from HVS
    TPML_DIGEST         pcrMeasurements[24];        // pcr measurments
    size_t              pcrsCollectedCount = 0;     // number of pcr measurements collected

    // TPML_PCR_SELECTION test = {0};
    // test.count = 1;
    // test.pcrSelections[0].hash = 0x04;
    // test.pcrSelections[0].sizeofSelect = 3;
    // test.pcrSelections[0].pcrSelect[0] = 0xff;
    // test.pcrSelections[0].pcrSelect[1] = 0xff;
    // test.pcrSelections[0].pcrSelect[2] = 0xff;

    rval = str2Tpm2bAuth(aikSecretKey, aikSecretKeyLength, &aikPassword);
    if(rval != 0)
    {
        ERROR("There was an error creating the aik TPM2B_AUTH");
        return rval;
    }

    if (pcrSelectionBytes == NULL || pcrSelectionBytesLength == 0 || pcrSelectionBytesLength > sizeof(TPML_PCR_SELECTION))
    {
        ERROR("Invalid pcrselection parameter");
        return -1;
    }

    pcrSelection = (TPML_PCR_SELECTION*)pcrSelectionBytes;

    if (qualifyingDataBytes == NULL || qualifyingDataBytesLength == 0 || qualifyingDataBytesLength > ARRAY_SIZE(qualifyingData.buffer))
    {
        ERROR("Invalid qualifying data parameter");
        return -1;
    }

    qualifyingData.size = qualifyingDataBytesLength;
    memcpy(&qualifyingData.buffer, qualifyingDataBytes, qualifyingDataBytesLength);

//    qualifyingData.size = 20;

    //
    // get the quote and signature information.  check results
    //
    rval = getQuote(ctx->sys, 
                    &aikPassword,       // KWT:  remove (confirm on hardware that not needed)
                    TPM_HANDLE_AIK,     // don't pass, move to getQuote
                    pcrSelection, 
                    &qualifyingData, 
                    &quote, 
                    &signature);

    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    FILE* f;
    if((f = fopen("/tmp/quote.bin", "wb")) != NULL)
    {
        fwrite(&quote, (quote.size + 2), 1, f);
    }
    fclose(f);

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

    // //
    // // get the pcr measurements
    // //
    // rval = getPcrs(ctx->sys, 
    //                pcrSelection,      
    //                pcrMeasurements,
    //                &pcrsCollectedCount);

    // if (rval != TSS2_RC_SUCCESS)
    // {
    //     return rval;
    // }

    // if (pcrsCollectedCount <=0 || pcrsCollectedCount > 24)
    // {
    //      ERROR("Incorrect amount of pcrs collected: x", pcrsCollectedCount)
    //      return -1;   
    // }

    // HVS wants a custom blob of data (format documented below based on) 
    // - TpmV20.java::getQuote() (where the bytes are created)
    // - 'QuoteResponse': https://github.com/microsoft/TSS.MSR/blob/master/TSS.Java/src/tss/tpm/QuoteResponse.java
    // - AikQuoteVerifier2.verifyAIKQuote() (where the bytes are consumed)
    //
    // 
    // TpmV20.java::getQuote(): Creates TpmQuote.quoteData bytes 'combined' from...
    //  - QuoteResponse.toTpm()
    //     - Quote...
    //       - 2 byte int of length of quote size
    //       - bytes from TPMS_ATTEST (this struture contains the selected pcrs in TPMU_ATTEST)
    //       ==> JUST WRITE TPM2B_ATTEST structure
    //     - Signature...
    //       - 2 bytes for signature algorithm
    //       - TPMU_SIGNATURE structure
    //       ==> JUST WRITE TPMT_SIGNATURE structure
    //  - pcrResults (concatentated buffers from TPM2B_DIGEST (TpmV20.java::getPcrs())).  Going to 
    //    assume full size of buffers (not using size)
    // 
    // ==> TPM2B_ATTEST
    //   - short of TPMS_ATTEST size
    //   - TPMS_ATTEST structure
    // ? ==> TPMT_SIGNATURE (QuoteResponse appears to include signature but it doesn't seem to be parsed in AikQuoteVerifier)
    // ?   - short of signature type
    // ?   - TPMU_SIGNATURE structure
    // ==> Selected PCRS
    //   - int32 of total number of pcr values
    //   - 'n' TPMS_PCR_SELECTION --> just buffer
    //
    // (all bytes are base64 encoded in go)

    TPMS_ATTEST* att = (TPMS_ATTEST*)&quote.attestationData;

    size_t bufferSize = sizeof(uint16_t) + quote.size + (sizeof(uint16_t)*3) + signature.signature.rsassa.sig.size;

    *quoteBytes = calloc(bufferSize, 1);
    if(!*quoteBytes) 
    {
        ERROR("Could not allocate quote buffer");
        return -1;
    }

    size_t off = 0;
    uint16_t tmp = __builtin_bswap16(quote.size);
    memcpy((*quoteBytes + off), &tmp, sizeof(uint16_t));
    off += sizeof(uint16_t);

     memcpy((*quoteBytes + off), &quote.attestationData, quote.size);
     off += quote.size;

    memcpy((*quoteBytes + off), &signature.sigAlg, sizeof(uint16_t));
    off += sizeof(uint16_t);

    memcpy((*quoteBytes + off), &signature.signature.rsassa.hash, sizeof(uint16_t));
    off += sizeof(uint16_t);

    tmp = __builtin_bswap16(signature.signature.rsassa.sig.size);
    memcpy((*quoteBytes + off), &tmp, sizeof(uint16_t));
    off += sizeof(uint16_t);

    memcpy((*quoteBytes + off), &signature.signature.rsassa.sig.buffer, signature.signature.rsassa.sig.size);
    off += signature.signature.rsassa.sig.size;

    *quoteBytesLength = bufferSize;
    return TSS2_RC_SUCCESS;
}