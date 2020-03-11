/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * common.h
 *
 *  Created on: 26-June-2018
 *      Author: Arvind Rawat
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "safe_lib.h"

/* un-comment to enable detailed command tracing */
//#define TPM_TRACE

#define CMD_HEAD_SIZE           10
#define RSP_HEAD_SIZE           10
#define CMD_SIZE_OFFSET         2
#define CMD_ORD_OFFSET          6
#define RSP_SIZE_OFFSET         2
#define RSP_RST_OFFSET          6

#define STDOUT stdout

int tpmfd;
typedef unsigned char byte;

/*
 * the following inline function reversely copy the bytes from 'in' to
 * 'out', the byte number to copy is given in count.
 */
#define reverse_copy(out, in, count) \
    _reverse_copy((uint8_t *)(out), (uint8_t *)(in), count)

static inline void _reverse_copy(uint8_t *out, uint8_t *in, uint32_t count)
{
	uint32_t i;
    for ( i = 0; i < count; i++ )
        out[i] = in[count - i - 1];
}

void PrintBytes(const char* szMsg, byte* pbData, int iSize);

#endif /* COMMON_H_ */
