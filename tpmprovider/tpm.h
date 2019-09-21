/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TPM_H__
#define __TPM_H__

#include <stdlib.h> // C.free
#include <stdint.h> // size_t, etc.

// just stuff that we expose to go (no platform specific defines/functions)

typedef struct tpmCtx tpmCtx;

typedef enum TPM_VERSION
{
	TPM_VERSION_UNKNOWN,
    TPM_VERSION_LINUX_20,
    TPM_VERSION_WINDOWS_20
} TPM_VERSION;

typedef enum NV_IDX 
{
    NV_IDX_ENDORSEMENT_KEY = 0x1c00002
} NV_IDX;

typedef enum TPM_HANDLE 
{
    TPM_HANDLE_EK_CERT  = 0x81010000,
    TPM_HANDLE_AIK      = 0x81018000
} TPM_HANDLE;

tpmCtx* TpmCreate();
void TpmDelete(tpmCtx* ctx);

TPM_VERSION Version(tpmCtx* ctx);
//int CreateCertifiedKey(char* keyAuth, char* aikAuth);
//int Unbind(ck *CertifiedKey, char* keyAuth, char* encData); // result buffer go allocated byte array passed in as reference, filled in by 'C' ([]byte, error)
//int Sign(ck *CertifiedKey, char* keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
int TakeOwnership(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength);
int IsOwnedWithAuth(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength);
int CreateEndorsementKey(const tpmCtx* ctx, const char* tpmSecretKey, size_t secretKeyLength);
int GetEndorsementKeyCertificate(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength, char** ekBytes, int* ekBytesLength);

int IsAikPresent(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength);
int CreateAik(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength);
int GetAikBytes(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength, char** aikBytes, int* aikBytesLength);
int GetAikName(tpmCtx* ctx, char* tpmSecretKey, size_t secretKeyLength, char** aikName, int* aikNameLength);

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
                       int *decryptedLength);

int NvIndexExists(tpmCtx* ctx, uint32_t nvIndex);
int PublicKeyExists(tpmCtx* ctx, uint32_t handle);
int ReadPublic(tpmCtx* ctx, uint32_t handle, char **public, int *publicLength);
//int SetCredential(authHandle uint, ownerAuth []byte, /*credentialType constants.CredentialType,*/ credentialBlob []byte) error
//int GetCredential(authHandle uint, /*credentialType constants.CredentialType*/) ([]byte, error)
//int GetAssetTag(authHandle uint) ([]byte, error)
//int GetAssetTagIndex() (uint, error)

#endif