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

tpmCtx* TpmCreate();
void TpmDelete(tpmCtx* ctx);

TPM_VERSION Version(tpmCtx* ctx);
//int CreateCertifiedKey(char* keyAuth, char* aikAuth);
//int Unbind(ck *CertifiedKey, char* keyAuth, char* encData); // result buffer go allocated byte array passed in as reference, filled in by 'C' ([]byte, error)
//int Sign(ck *CertifiedKey, char* keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
int TakeOwnership(tpmCtx* ctx, char* secretKey, size_t keyLen);
int IsOwnedWithAuth(tpmCtx* ctx, char* secretKey, size_t keyLen);
int CreateEndorsementKey(tpmCtx* ctx, char* secretKey, size_t keyLength);
int GetEndorsementKeyCertificate(tpmCtx* ctx, char* secretKey, size_t keyLength, char** ekBytes, int* ekBytesLength);
int NvIndexExists(tpmCtx* ctd, uint32_t nvIndex);
int PublicKeyExists(tpmCtx* ctd, uint32_t handle);
//int SetCredential(authHandle uint, ownerAuth []byte, /*credentialType constants.CredentialType,*/ credentialBlob []byte) error
//int GetCredential(authHandle uint, /*credentialType constants.CredentialType*/) ([]byte, error)
//int GetAssetTag(authHandle uint) ([]byte, error)
//int GetAssetTagIndex() (uint, error)

#endif