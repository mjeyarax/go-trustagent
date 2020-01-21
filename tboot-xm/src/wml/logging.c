/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * logging.c
 *
 *  Created on: 14-June-2018
 *      Author: Arvind Rawat
 */

#include <fcntl.h>

#include "common.h"
#include "logging.h"
#include "log.h"

#define default_log_file "/var/log/wml/measure.log"
#define default_log_level LOG_INFO

static const char *level_names[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

int str2enum (const char *str)
{
    int i;
    for (i = 0; i < sizeof(level_names)/sizeof(level_names[0]); i++) {
        if (!strcmp(str, level_names[i])) {
            return i;
		}
	}
	
	return -1;
}

FILE* configure_logger() {

	int fd = -1;
	FILE *fp = NULL;
	int log_level = -1;
	char *log_file = NULL;

	const char* lf = getenv("WML_LOG_FILE");
	if (lf != NULL) {
		log_file = realpath(lf, NULL);
		if (log_file == NULL) {
			printf("Invalid log file specified\n");
			return NULL;
		}

		fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fd == -1) {
			printf("Unable to get file descriptor for log file\n");
			free(log_file);
			return NULL;
		}

		fp = fdopen(fd, "a");
		free(log_file);
	}
	else {
		fp = fopen(default_log_file, "w");
	}
	
	if (fp == NULL) {
		printf("Unable to open log file\n");
		return NULL;
	}
	
	const char* ll = getenv("WML_LOG_LEVEL");
	if (ll != NULL) {
		log_level = str2enum(ll);
		if (log_level == -1) {
			printf("Invalid log level specified\n");
			fclose(fp);
			return NULL;
		}
	}
	else {
		log_level = default_log_level;
	}
	
	log_set_fp(fp);
	log_set_level(log_level);
	log_set_quiet(1);
	return fp;
}
