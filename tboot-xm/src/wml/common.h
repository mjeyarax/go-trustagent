/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * common.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "safe_lib.h"
#include "log.h"

#define MAX_CMD_LEN ARG_MAX
#define MAX_LEN 4096
#define NODE_LEN 512

char node_value[NODE_LEN];
char fs_mount_path[NODE_LEN];

#endif /* COMMON_H_ */
