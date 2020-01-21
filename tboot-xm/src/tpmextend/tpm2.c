/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * tpm2.c
 *
 *  Created on: 26-June-2018
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "tpm2.h"

/*
 * specified as minimum cmd buffer size should be supported by all 2.0 TPM device
 */
#define TPM_CMD_SIZE_MAX	4096
#define TPM_RSP_SIZE_MAX	4096

#define TPM_CC_PCR_EXTEND       0x00000182
#define TPM_CC_PCR_READ         0x0000017E
#define TPM_CC_PCR_RESET        0x0000013D
#define TPM_CC_NV_READ          0x0000014E
#define TPM_CC_NV_WRITE         0x00000137
#define TPM_CC_GET_RANDOM       0x0000017B

#define TPM_TAG_PCR_INFO_LONG   0x0006
#define TPM_TAG_STORED_DATA12   0x0016

static uint8_t     		cmd_buf[TPM_CMD_SIZE_MAX];
static uint8_t     		rsp_buf[TPM_RSP_SIZE_MAX];
#define WRAPPER_IN_BUF          (cmd_buf + CMD_HEAD_SIZE)
#define WRAPPER_OUT_BUF         (rsp_buf + RSP_HEAD_SIZE)
#define WRAPPER_IN_MAX_SIZE     (TPM_CMD_SIZE_MAX - CMD_HEAD_SIZE)
#define WRAPPER_OUT_MAX_SIZE    (TPM_RSP_SIZE_MAX - RSP_HEAD_SIZE)

static uint32_t tpm_write_cmd_fifo(uint8_t *in, uint32_t in_size, uint8_t *out, uint32_t *out_size) {

    if ( in == NULL || out == NULL || out_size == NULL ) {
        fprintf(STDOUT, "TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return TPM_RC_TAG;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE ) {
        fprintf(STDOUT, "TPM: in/out buf size must be larger than 10 bytes\n");
        return TPM_RC_COMMAND_SIZE;
    }

#ifdef TPM_TRACE
    {
        fprintf(STDOUT, "TPM: cmd size = %d\nTPM: cmd content: ", in_size);
        print_hex("TPM: \t", in, in_size);
    }
#endif
	int ret = write(tpmfd, in, in_size);
	if(ret<0){
        fprintf(STDOUT, "write failed, ret %d\n", ret);
        close(tpmfd);
        return ret;
    }
    return ret;
}

static uint32_t _tpm_submit_cmd(uint16_t tag, uint32_t cmd, uint32_t arg_size, uint32_t *out_size)
{
    uint32_t    ret;
    uint32_t    cmd_size, rsp_size = 0;

    if ( out_size == NULL ) {
        fprintf(STDOUT, "TPM: invalid param for _tpm_submit_cmd()\n");
        return TPM_RC_TAG;
    }

    /*
     * real cmd size should add 10 more bytes:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for ordinal
     */
    cmd_size = CMD_HEAD_SIZE + arg_size;

    if ( cmd_size > TPM_CMD_SIZE_MAX ) {
        fprintf(STDOUT, "TPM: cmd exceeds the max supported size.\n");
        return TPM_RC_COMMAND_SIZE;
    }

    /* copy tag, size & ordinal into buf in a reversed byte order */
    reverse_copy(cmd_buf, &tag, sizeof(tag));
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));
    reverse_copy(cmd_buf + CMD_ORD_OFFSET, &cmd, sizeof(cmd));

	PrintBytes("TPM: CMD_BUF ", cmd_buf, cmd_size);
	fprintf(STDOUT, "cmd_buf ready, call tpm_write_cmd_fifo next\n");

    rsp_size = RSP_HEAD_SIZE + *out_size;
    rsp_size = (rsp_size > TPM_RSP_SIZE_MAX) ? TPM_RSP_SIZE_MAX: rsp_size;
    ret = tpm_write_cmd_fifo(cmd_buf, cmd_size, rsp_buf, &rsp_size);

	fprintf(STDOUT, "after tpm_write_cmd_fifo, ret=%d\n", ret);
	PrintBytes("TPM: RSP_BUF ", rsp_buf, rsp_size);

    /*
     * should subtract 10 bytes from real response size:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for return code
     */
    rsp_size -= (rsp_size > RSP_HEAD_SIZE) ? RSP_HEAD_SIZE : rsp_size;

    if ( ret != TPM_RC_SUCCESS )
        return ret;

    if ( *out_size == 0 || rsp_size == 0 )
        *out_size = 0;
    else
        *out_size = (rsp_size < *out_size) ? rsp_size : *out_size;

    return ret;
}

static inline uint32_t tpm_submit_cmd(uint16_t tag, uint32_t cmd, uint32_t arg_size, uint32_t *out_size)
{
   return  _tpm_submit_cmd(tag, cmd, arg_size, out_size);
}

UINT32 tpm_pcr_extend2(tpmi_dh_pcr handle, tpmi_alg_hash hash, UINT32 size, BYTE *data)
{
	UINT32 ret;
	UINT32 in_size = 0;
	UINT32 out_size = 0;
    UINT32 pcr = handle;
	UINT32 auth_size = sizeof(UINT32)+sizeof(UINT16)+sizeof(BYTE)+sizeof(UINT16);

	fprintf(STDOUT, "TPM: Pcr %d extend\n", pcr);
	fprintf(STDOUT, "TPM: Hash %d extend\n", hash);
	fprintf(STDOUT, "TPM: Size %d extend\n", size);
    PrintBytes("TPM: Data ", data, size);

	if (pcr > TPM_NR_PCRS)
		return TPM_RC_VALUE;
	if (pcr == TPM_RH_NULL)
		return TPM_RC_SUCCESS;

	tpmu_ha tu;
	memcpy_s(tu.sha256, SHA256_DIGEST_SIZE, data, size);

	tpmt_ha tt;
	tt.hash_alg = hash;
	tt.digest = tu;

	tpml_digest_values tl;
	tl.count = 1;
	tl.digests[0] = tt;

	tpml_digest_values *in = &tl;

	fprintf(STDOUT, "TPM: Count %d extend\n", in->count);
	fprintf(STDOUT, "TPM: Hash_Alg %d extend\n", in->digests[0].hash_alg);
	PrintBytes("TPM: Digest ", in->digests[0].digest.sha256, size);

	tpm2b_digest nonce;
	nonce.size = 0;
	memset(nonce.buffer, 0, nonce.size);

	tpm2b_digest auth;
	auth.size = 0;
	memset(auth.buffer, 0, auth.size);

	tpms_auth_command ts;
	ts.session_handle = TPM_RS_PW;
	ts.nonce = nonce;
	ts.session_attributes = 0;
	ts.auth = auth;

	tpms_auth_command *auth_area = &ts;

	fprintf(STDOUT, "TPM: Session_Handle %08X extend\n", auth_area->session_handle);
	fprintf(STDOUT, "TPM: Nonce_Size %d extend\n", auth_area->nonce.size);
	fprintf(STDOUT, "TPM: Auth_Size %d extend\n", auth_area->auth.size);
	fprintf(STDOUT, "TPM: Session_Attributes %d extend\n", auth_area->session_attributes);

	/* copy pcr into buf in reversed byte order, then copy in data */
	reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));
	in_size += sizeof(pcr);
	reverse_copy(WRAPPER_IN_BUF + in_size, &auth_size, sizeof(auth_size));
	in_size += sizeof(auth_size);
	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.session_handle), sizeof(ts.session_handle));
	in_size += sizeof(ts.session_handle);
	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.nonce.size), sizeof(UINT16));
	in_size += sizeof(UINT16);
	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.session_attributes), sizeof(ts.session_attributes));
	in_size += sizeof(ts.session_attributes);
	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.auth.size), sizeof(UINT16));
	in_size += sizeof(UINT16);
	reverse_copy(WRAPPER_IN_BUF + in_size, &(tl.count), sizeof(tl.count));
	in_size += sizeof(tl.count);
	reverse_copy(WRAPPER_IN_BUF + in_size, &(tl.digests[0].hash_alg), sizeof(tl.digests[0].hash_alg));
	in_size += sizeof(tl.digests[0].hash_alg);
	memcpy_s(WRAPPER_IN_BUF + in_size, WRAPPER_IN_MAX_SIZE-in_size, tl.digests[0].digest.sha256, size);
	in_size += size;

	fprintf(STDOUT, "TPM: In_Size %d extend\n", in_size);
	PrintBytes("TPM: WRAPPER_IN_BUF ", WRAPPER_IN_BUF, in_size);

	ret = tpm_submit_cmd(TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND, in_size, &out_size);

#ifdef TPM_TRACE
    fprintf(STDOUT, "TPM: Pcr %d extend, return value = %08X\n", handle, ret);
#endif
    if ( ret != TPM_RC_SUCCESS ) {
       	fprintf(STDOUT, "TPM: Pcr %d extend, return value = %08X\n", handle, ret);
       	return ret;
    }

	fprintf(STDOUT, "TPM: Out_Size %d read\n", out_size);

    return ret;
}

UINT32 tpm_pcr_read2(tpml_pcr_selection *selection, tpml_digest *digest, UINT32 pcr_counter)
{
	UINT32 ret;
	UINT32 in_size = 0;
	UINT32 out_size = sizeof(*selection) + sizeof(*digest) + sizeof(pcr_counter);
	
	fprintf(STDOUT, "TPM: Selection_Count %d read\n", selection->count);
	fprintf(STDOUT, "TPM: Selection_Hash %d read\n", selection->pcr_selections[0].hash);
	fprintf(STDOUT, "TPM: Selection_SizeofSelect %d read\n", selection->pcr_selections[0].size_of_select);
	PrintBytes("TPM: Selection_PcrSelect ", selection->pcr_selections[0].pcr_select, selection->pcr_selections[0].size_of_select);

	if (selection->count > HASH_COUNT)
		return TPM_RC_SIZE;
    if (selection->pcr_selections[0].size_of_select > PCR_SELECT_MAX)
		return TPM_RC_VALUE;

	/* copy pcr into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &(selection->count), sizeof(UINT32));
	in_size += sizeof(UINT32);
    reverse_copy(WRAPPER_IN_BUF + in_size, &(selection->pcr_selections[0].hash), sizeof(UINT16));
	in_size += sizeof(UINT16);
    reverse_copy(WRAPPER_IN_BUF + in_size, &(selection->pcr_selections[0].size_of_select), sizeof(UINT8));
	in_size += sizeof(UINT8);
    memcpy_s(WRAPPER_IN_BUF + in_size, WRAPPER_IN_MAX_SIZE-in_size, selection->pcr_selections[0].pcr_select, sizeof(selection->pcr_selections[0].pcr_select));
	in_size += sizeof(selection->pcr_selections[0].pcr_select);
    	
	fprintf(STDOUT, "TPM: In_Size %d read\n", in_size);
	PrintBytes("TPM: WRAPPER_IN_BUF ", WRAPPER_IN_BUF, in_size);

    ret = tpm_submit_cmd(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, in_size, &out_size);

#ifdef TPM_TRACE
    fprintf(STDOUT, "TPM: Pcr %d Read, return value = %08X\n", pcr_counter, ret);
#endif
    if ( ret != TPM_RC_SUCCESS ) {
        fprintf(STDOUT, "TPM: Pcr %d %d %d Read not successful, return value = %08X\n", selection->pcr_selections[0].pcr_select[0], selection->pcr_selections[0].pcr_select[1], selection->pcr_selections[0].pcr_select[2], ret);
        return ret;
    }

	fprintf(STDOUT, "TPM: Out_Size %d read\n", out_size);

    if ( out_size > (sizeof(*selection) + sizeof(*digest) + sizeof(pcr_counter)) ) {
       	out_size = sizeof(*selection) + sizeof(*digest) + sizeof(pcr_counter);
	}

	in_size = 0;
    reverse_copy((void *)&pcr_counter, WRAPPER_OUT_BUF, sizeof(pcr_counter));
	fprintf(STDOUT, "TPM: Pcr_Counter %d read\n", pcr_counter);
	in_size += sizeof(pcr_counter) + 10;
    reverse_copy((void *)&(digest->count), WRAPPER_OUT_BUF + in_size, sizeof(digest->count));
	fprintf(STDOUT, "TPM: Digest_Count %d read\n", digest->count);
	in_size += sizeof(digest->count);
    reverse_copy((void *)&(digest->digests[0].size), WRAPPER_OUT_BUF + in_size, sizeof(digest->digests[0].size));
	fprintf(STDOUT, "TPM: Digest_Size %d read\n", digest->digests[0].size);
	in_size += sizeof(digest->digests[0].size);
    memcpy_s((void *)digest->digests[0].buffer, SHA256_DIGEST_SIZE, WRAPPER_OUT_BUF + in_size, digest->digests[0].size);
	PrintBytes("TPM: Digest_Buffer : ", digest->digests[0].buffer, digest->digests[0].size);

#ifdef TPM_TRACE
    {
       	fprintf(STDOUT, "TPM: ");
       	print_hex(NULL, digest->digests[0].buffer, digest->digests[0].size);
    }
#endif

   	return ret;
}
