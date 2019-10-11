/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TPM_H__
#define __TPM_H__

#include <stdlib.h> // C.free
#include <stdint.h> // size_t, etc.

// KWT: document fx, etc.

typedef struct tpmCtx tpmCtx;

typedef enum TPM_VERSION
{
	TPM_VERSION_UNKNOWN,
    TPM_VERSION_LINUX_20,
    TPM_VERSION_WINDOWS_20
} TPM_VERSION;

typedef enum NV_IDX 
{
    NV_IDX_ENDORSEMENT_KEY  = 0x1c00002,
    NV_IDX_ASSET_TAG        = 0x1c10110
} NV_IDX;

typedef enum TPM_HANDLE 
{
    TPM_HANDLE_EK_CERT  = 0x81010000,
    TPM_HANDLE_AIK      = 0x81018000,
} TPM_HANDLE;

tpmCtx* TpmCreate();
void TpmDelete(tpmCtx* ctx);

TPM_VERSION Version(tpmCtx* ctx);
//int CreateCertifiedKey(char* keyAuth, char* aikAuth);
//int Unbind(ck *CertifiedKey, char* keyAuth, char* encData); // result buffer go allocated byte array passed in as reference, filled in by 'C' ([]byte, error)
//int Sign(ck *CertifiedKey, char* keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
int TakeOwnership(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength);
int IsOwnedWithAuth(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength);

//int IsAikPresent(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength);
int CreateAik(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength, char* aikSecretKey, size_t aikSecretKeyLength);
int GetAikBytes(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength, char** aikBytes, int* aikBytesLength);
int GetAikName(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength, char** aikName, int* aikNameLength);

int GetTpmQuote(tpmCtx* ctx, 
                char* aikSecretKey, 
                size_t aikSecretKeyLength, 
                void* pcrSelectionBytes,
                size_t pcrSelectionBytesLength,
                void* qualifyingDataString,
                size_t qualifyingDataStringLength,
                char** quoteBytes, 
                int* quouteBytesLength);

int ActivateCredential(tpmCtx* ctx, 
                       char* tpmOwnerSecretKey, 
                       size_t tpmOwnerSecretKeyLength,
                       char* aikSecretKey, 
                       size_t aikSecretKeyLength,
                       void* credentialBytes, 
                       size_t credentialBytesLength,
                       void* secretBytes, 
                       size_t secretBytesLength,
                       char **decrypted,
                       int *decryptedLength);

int NvIndexExists(tpmCtx* ctx, uint32_t nvIndex);
int NvDefine(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength, uint32_t nvIndex, uint16_t nvSize);
int NvRead(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength, uint32_t nvIndex, char** nvBytes, int* nvBytesLength);
int NvWrite(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLength, uint32_t nvIndex, void* nvBytes, size_t nvBytesLength);
int NvRelease(tpmCtx* ctx, char* tpmOwnerSecretKey, size_t tpmOwnerSecretKeyLenth, uint32_t nvIndex);
int PublicKeyExists(tpmCtx* ctx, uint32_t handle);
int ReadPublic(tpmCtx* ctx, uint32_t handle, char **public, int *publicLength);

//int GetAssetTag(authHandle uint) ([]byte, error)
//int GetAssetTagIndex() (uint, error)

#endif