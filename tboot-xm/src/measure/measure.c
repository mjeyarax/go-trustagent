/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * measure.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include <stdio.h>

#include "measurement.h"

/*
* Main function which checks for the different input parameters
* provided to the measure and calls a workload measurement library
*/
int main(int argc, char **argv) {

	if(argc != 3) {
        printf("Usage: measure <manifest_xml> <mounted_path>\n");
        return -1;
    }
	
	char *measurements = measure(argv[1], argv[2]);
	if (measurements == NULL) {
		printf("Failed to generate measurement xml\n");
		return -1;
	}
	printf("%s", measurements);

	return 0;
}
