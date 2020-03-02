/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * tpm2.h
 *
 *  Created on: 26-June-2018
 *      Author: Arvind Rawat
 */

#ifndef TPM2_H_
#define TPM2_H_

/*
 * return code:
 * The TPM has five types of return code. One indicates successful operation
 * and four indicate failure.
 * TPM_SUCCESS (00000000) indicates successful execution.
 * The failure reports are:
 *      TPM defined fatal errors (00000001 to 000003FF)
 *      vendor defined fatal errors (00000400 to 000007FF)
 *      TPM defined non-fatal errors (00000800 to 00000BFF)
 *      vendor defined non-fatal errors (00000C00 to 00000FFF).
 * Here only give definitions for a few commonly used return code.
 */
#define RC_VER1			0x100
#define RC_FMT1			0x080
#define RC_WARN			0x900
#define TPM_RC_SUCCESS		0x000
#define TPM_RC_BAD_TAG		0x01E
#define TPM_RC_FAILURE		(RC_VER1 + 0x001)
#define TPM_RC_DISABLED		(RC_VER1 + 0x020)
#define TPM_RC_NV_SIZE		(RC_VER1 + 0x047)
#define TPM_NV_SPACE		(RC_VER1 + 0x04B)
#define TPM_RC_PCR		(RC_VER1 + 0x027)
#define TPM_RC_PCR_CHANGED	(RC_VER1 + 0x028)
#define TPM_RC_COMMAND_CODE	(RC_VER1 + 0x043)
#define TPM_RC_COMMAND_SIZE	(RC_VER1 + 0x042)
#define TPM_RC_TAG		(RC_FMT1 + 0x017)
#define TPM_RC_SIZE		(RC_FMT1 + 0x015)
#define TPM_RC_VALUE		(RC_FMT1 + 0x004)
#define TPM_RC_LOCALITY		(RC_WARN + 0x007)
#define TPM_RC_RETRY		(RC_WARN + 0x022)

#define TPM_RH_NULL 		0x40000007
#define TPM_RS_PW		0x40000009

#define PT_GROUP		0x00000100
#define PT_FIXED		(PT_GROUP * 1)
#define TPM_PT_PCR_COUNT	(PT_FIXED + 18)
#define TPM_PT_PCR_SELECT_MIN	(PT_FIXED + 19)
#define TPM_PT_MAX_COMMAND_SIZE	(PT_FIXED + 30)
#define TPM_PT_MAX_RESP_SIZE	(PT_FIXED + 31)
#define TPM_PT_MAX_DIGEST	(PT_FIXED + 32)

#define NV_INDEX_SIZE_MAX	2048
#define NV_BUFFER_SIZE_MAX	1024
#define NV_MEMORY_SIZE		16384
#define MAX_DIGEST_BUFFER	1024

#define TPM_ALG_ERROR		0x0000
#define TPM_ALG_NULL		0x0010
#define TPM_ALG_SHA1		0x0004
#define TPM_ALG_SHA256		0x000B

#define TPM_ST_NULL		0x8000
#define TPM_ST_NO_SESSIONS	0x8001
#define TPM_ST_SESSIONS		0x8002
#define TPM_ST_RSP_COMMAND	0x00C4

#define SHA1_DIGEST_SIZE	20
#define SHA256_DIGEST_SIZE	32

#define HASH_COUNT		2
#define TPM_NR_PCRS         	24
#define PCR_SELECT_MAX		((TPM_NR_PCRS+7)/8)

#define UINT8 uint8_t //unsigned, 8-bit integer
#define BYTE uint8_t //unsigned 8-bit integer
#define INT8 int8_t //signed, 8-bit integer
#define BOOL int //a bit in an int
#define UINT16 uint16_t //unsigned, 16-bit integer
#define INT16 int16_t //signed, 16-bit integer
#define UINT32 uint32_t //unsigned, 32-bit integer
#define INT32 int32_t //signed, 32-bit integer
#define UINT64 uint64_t //unsigned, 64-bit integer
#define INT64 int64_t //signed, 64-bit integer

typedef	UINT16 tpm_alg_id;

typedef UINT32 tpm_handle;

typedef tpm_handle tpmi_dh_pcr;

typedef tpm_handle tpmi_sh_auth_session;

typedef tpm_alg_id tpmi_alg_hash;

typedef UINT16 tpm_st;

typedef tpm_st tpmi_st_command_tag;

typedef UINT8 tpma_session;

typedef struct __attribute__((packed)) {
	tpmi_alg_hash hash;
	UINT8 size_of_select;
	BYTE pcr_select[PCR_SELECT_MAX];
}tpms_pcr_selection;

typedef struct __attribute__((packed)) {
	UINT32 count;
	tpms_pcr_selection pcr_selections[HASH_COUNT];
}tpml_pcr_selection;

typedef union __attribute__((packed)) {
	BYTE sha1[SHA1_DIGEST_SIZE];
	BYTE sha256[SHA256_DIGEST_SIZE];
}tpmu_ha;

typedef struct __attribute__((packed)) {
	tpmi_alg_hash hash_alg;
	tpmu_ha digest;
}tpmt_ha;

typedef struct __attribute__((packed)) {
	UINT32 count;
	tpmt_ha digests[HASH_COUNT];
}tpml_digest_values;

typedef struct __attribute__((packed)) {
	UINT16 size;
	BYTE buffer[sizeof(tpmu_ha)];
}tpm2b_digest;

typedef tpm2b_digest tpm2b_nonce;

typedef tpm2b_digest tpm2b_auth;

typedef struct __attribute__((packed)) {
	UINT32 count;
	tpm2b_digest digests[8];
}tpml_digest;

typedef struct __attribute__((packed)) {
	tpmi_sh_auth_session session_handle;
	tpm2b_nonce nonce;
	tpma_session session_attributes;
	tpm2b_auth auth;
}tpms_auth_command;

UINT32 tpm_pcr_read2(tpml_pcr_selection *selection, tpml_digest *digest, UINT32 pcr_counter);

UINT32 tpm_pcr_extend2(tpmi_dh_pcr handle, tpmi_alg_hash hash, UINT32 size, BYTE *data);

#endif /* TPM2_H_ */
