/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * char_converter.h
 *
 *  Created on: 24-May-2018
 *      Author: Arvind Rawat
 */

#ifndef CHAR_CONVERTER_H_
#define CHAR_CONVERTER_H_

int hex2bin(char *hex_str, int hex_str_len, unsigned char *byte_buffer, int byte_buffer_len);
int bin2hex(unsigned char * byte_buffer, int byte_buffer_len, char * hex_str, int hex_str_len);

#endif /* CHAR_CONVERTER_H_ */
