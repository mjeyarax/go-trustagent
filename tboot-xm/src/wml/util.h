/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * util.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <regex.h>

#define temp_file "/tmp/temp.txt"

#define WS_NONE         0
#define WS_RECURSIVE    (1 << 0)
#define WS_DEFAULT      WS_RECURSIVE
#define WS_LINK         (1 << 1)
#define WS_FILES        (1 << 2)
#define WS_DIRS         (1 << 3)

char *toUpperCase(char *str);
void tagEntry(char* line);
char *getTagValue(char *line, char *key);
void convertWildcardToRegex(char *wildcard);
char *tokenizeString(char *line, char *delim);
FILE *getMatchingEntries(char *line, FILE *fd, int spec);
void replaceAllStr(char * orig_str, char * search_str, char * replace_str);

void calculateSymlinkHashUtil(char *sym_path, FILE *fq);
void calculateFileHashUtil(char *file_path, FILE *fq);
void calculateDirHashUtil(char *dir_path, char *include, char *exclude, regex_t *reginc, regex_t *regexc, FILE *fq);

#endif /* UTIL_H_ */
