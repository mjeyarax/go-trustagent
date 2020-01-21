/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * xml_formatter.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "xml_formatter.h"

FILE *formatManifestXml(char *manifest_xml, FILE *fd) {

	char Cmd_Str[MAX_CMD_LEN] = {'\0'};
	snprintf(Cmd_Str, sizeof(Cmd_Str), "echo '%s' | xmllint --format -", manifest_xml);
	log_info("********manifest_xml is ---------- %s and command is %s",manifest_xml,Cmd_Str);
	
	fd = popen(Cmd_Str,"r");
	return fd;
}
