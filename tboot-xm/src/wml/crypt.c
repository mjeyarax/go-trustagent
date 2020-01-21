/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * crypt.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include <openssl/evp.h>

#include "common.h"
#include "char_converter.h"
#include "crypt.h"

//For Openssl EVP APIs
const EVP_MD	*md;

/*These global variables are required for calculating the cumulative hash */
unsigned int cumulative_hash_len = 0;
unsigned char cumulative_hash[MAX_HASH_LEN] = {'\0'};

static const char *hash_algorithms[] = {
	"SHA384"
};

int validateHashAlgorithm(char *hash_type) {

	int i;
	for (i = 0; i < sizeof(hash_algorithms) / sizeof(hash_algorithms[0]); i++)
	if (!strcmp(hash_type, hash_algorithms[i]))
		return 1;
	return 0;
}

int initializeHashAlgorithm(char *hash_type) {

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hash_type);
	if (md == NULL) {
		log_error("Digest Algorithm not supported by Openssl : %s", hash_type);
		return 0;
	}

	cumulative_hash_len = EVP_MD_size(md);
	return 1;
}

/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generateCumulativeHash(char *hash) {

    log_debug("Incoming Hash : %s", hash);
	char ob[MAX_HASH_LEN]= {'\0'};
	char cur_hash[MAX_HASH_LEN] = {'\0'};

	int cur_hash_len = hex2bin(hash, strnlen_s(hash, MAX_HASH_LEN), (unsigned char *)cur_hash, sizeof(cur_hash));
	bin2hex(cumulative_hash, cumulative_hash_len, ob, sizeof(ob));
	log_debug("Cumulative Hash before : %s", ob);

	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);

	EVP_DigestUpdate(mdctx, cumulative_hash, cumulative_hash_len);
	if (cur_hash_len == cumulative_hash_len) {
		EVP_DigestUpdate(mdctx, cur_hash, cur_hash_len);
	}
	else {
		log_warn("length of string converted from hex is : %d not equal to expected hash digest length : %d", cur_hash_len, cumulative_hash_len);
		log_warn("ERROR: current hash is not being updated in cumulative hash");
	}

	//Dump the hash in variable and destroy the mdctx context
	EVP_DigestFinal_ex(mdctx, cumulative_hash, &cumulative_hash_len);
	EVP_MD_CTX_destroy(mdctx);

	bin2hex(cumulative_hash, cumulative_hash_len, ob, sizeof(ob));
	log_debug("Cumulative Hash after : %s", ob);
}

void generateFileHash(char *output, FILE *file) {

	int bytesRead = 0;
	const int bufSize = 65000;
	unsigned char hash_value[MAX_HASH_LEN];

    char *buffer = (char *)malloc(bufSize);
    if(!buffer) {
		log_error("Can't allocate memory for buffer");
        return;
    }

	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	while ((bytesRead = fread(buffer, 1, bufSize, file))) {
		// calculate hash of bytes read
		EVP_DigestUpdate(mdctx, buffer, bytesRead);
	}

	//Dump the hash in variable and destroy the mdctx context
	EVP_DigestFinal_ex(mdctx, hash_value, &cumulative_hash_len);
	EVP_MD_CTX_destroy(mdctx);

	bin2hex(hash_value, cumulative_hash_len, output, MAX_HASH_LEN);
	generateCumulativeHash(output);
	free(buffer);
}

void generateStrHash(char *output, char *str) {

	unsigned char hash_value[MAX_HASH_LEN];
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, str, strnlen_s(str, MAX_LEN));

	//Dump the hash in variable and destroy the mdctx context
	EVP_DigestFinal_ex(mdctx, hash_value, &cumulative_hash_len);
	EVP_MD_CTX_destroy(mdctx);

	bin2hex(hash_value, cumulative_hash_len, output, MAX_HASH_LEN);
	generateCumulativeHash(output);
}
