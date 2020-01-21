/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * measurement.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

/* Workload Measurement Library - Litev1
@AR
Intel Corp - CSS-DCG
Hard requirements: Manifest should be named manifest.xml - Parameters should be passed on command line using the entire file/directory path
Keywords in the Policy should match with those in this code : DigestAlg, File Path, Dir, sha1 and sha256
*/

#include "common.h"
#include "logging.h"
#include "crypt.h"
#include "util.h"
#include "char_converter.h"
#include "xml_formatter.h"
#include "measurement.h"

#define measurement_file "/tmp/measurement.xml"

/*These global variables are required for calculating the cumulative hash */
extern unsigned int cumulative_hash_len;
extern unsigned char cumulative_hash[MAX_HASH_LEN];

 /*
 * calculateSymlinkHash:
 * @line : path of the symlink
 * @fq : measurement_file pointer
 *
 * Calculate hash of symlink
 */
void calculateSymlinkHash(char *line, FILE *fq) {

    size_t len = 32768;
	char sym_path[NODE_LEN] = {'\0'};
    FILE *fd = NULL;

    if (getTagValue(line, "Path=")) {
		strcpy_s(sym_path,sizeof(sym_path),node_value);
		log_info("Symlink : %s",node_value);
	}

	if (strcmp(sym_path, "") == 0) {
		log_warn("Path is not provided. Skipping measurement...");
		return;
	}

	if (strstr(line, "SearchType=")) {
		fd = getMatchingEntries(sym_path, fd, WS_LINK);
		if (fd != NULL) {
			while (fgets(line, len, fd) != NULL) {
				log_debug("Entry Read : %s",line);
				if(feof(fd)) {
					log_debug("End of Entries found");
					break;
				}
				strcpy_s(sym_path,NODE_LEN,tokenizeString(line, "\n"));
				calculateSymlinkHashUtil(sym_path, fq);
			}
			fclose(fd);
		}
	}
	else {
		calculateSymlinkHashUtil(sym_path, fq);
	}
}

 /*
 * calculateFileHash:
 * @line : path of the file
 * @fq : measurement_file pointer
 *
 * Calculate hash of file
 */
void calculateFileHash(char *line, FILE *fq) {

    size_t len = 32768;
    char file_path[NODE_LEN] = {'\0'};
    FILE *fd = NULL;

	if (getTagValue(line, "Path=")) {
		strcpy_s(file_path,sizeof(file_path),node_value);
		log_info("File : %s",node_value);
	}
	
	if (strcmp(file_path, "") == 0) {
		log_warn("Path is not provided. Skipping measurement...");
		return;
	}

	if (strstr(line, "SearchType=")) {
		fd = getMatchingEntries(file_path, fd, WS_FILES);
		if (fd != NULL) {
			while (fgets(line, len, fd) != NULL) {
				log_debug("Entry Read : %s",line);
				if(feof(fd)) {
					log_debug("End of Entries found");
					break;
				}
				strcpy_s(file_path,NODE_LEN,tokenizeString(line, "\n"));
				calculateFileHashUtil(file_path, fq);
			}
			fclose(fd);
		}
	}
	else {
		calculateFileHashUtil(file_path, fq);
	}
}

 /*
 * calculateDirHash:
 * @line : path of the dir
 * @fq : measurement_file pointer
 *
 * Calculate hash of dir
 */
void calculateDirHash(char *line, FILE *fq) {

    size_t len = 32768;
    int is_wildcard = 0;
	char dir_path[NODE_LEN] = {'\0'};
	char filter_type[32] = {'\0'};
    char exclude[32] = { '\0'};
    char include[32] = {'\0'};
    regex_t reginc, regexc;
    FILE *fd = NULL;
    
    if (getTagValue(line, "Path=")) {
		strcpy_s(dir_path,sizeof(dir_path),node_value);
		log_info("Directory : %s",node_value);
	}
	
	if (strcmp(dir_path, "") == 0) {
		log_warn("Path is not provided. Skipping measurement...");
		return;
	}

	if (getTagValue(line, "FilterType=")) {
		strcpy_s(filter_type,sizeof(filter_type),node_value);
		log_info("FilterType : %s",node_value);
		if(strcmp(filter_type, "wildcard") == 0) {
			is_wildcard = 1;
		}
	}

	if (getTagValue(line, "Include=")) {
		strcpy_s(include,sizeof(include),node_value);
		log_info("Include : %s",node_value);
		if (strcmp(include, "") != 0) {
			if (is_wildcard == 1) {
				convertWildcardToRegex(include);
				strcpy_s(include,sizeof(include),node_value);
				log_info("Include type in regex_format : %s",node_value);
			}
			if (regcomp(&reginc, include, REG_EXTENDED | REG_NOSUB)) {
				log_warn("Not a valid regex. Skipping measurement...");
				return;
			}
		}
	}

    if (getTagValue(line, "Exclude=")) {
		strcpy_s(exclude,sizeof(exclude),node_value);
		log_info("Exclude : %s",node_value);
		if (strcmp(exclude, "") != 0) {
			if (is_wildcard == 1) {
				convertWildcardToRegex(exclude);
				strcpy_s(exclude,sizeof(exclude),node_value);
				log_info("Exclude type in regex_format : %s",node_value);
			}
			if (regcomp(&regexc, exclude, REG_EXTENDED | REG_NOSUB)) {
				log_warn("Not a valid regex. Skipping measurement...");
				return;
			}
		}
	}

	if (strstr(line, "SearchType=")) {
		fd = getMatchingEntries(dir_path, fd, WS_DIRS);
		if (fd != NULL) {
			while (fgets(line, len, fd) != NULL) {
				log_debug("Line Read : %s", line);
				if(feof(fd)) {
					log_debug("End of Entries found");
					break;
				}
				strcpy_s(dir_path,NODE_LEN,tokenizeString(line, "\n"));
				calculateDirHashUtil(dir_path, include, exclude, &reginc, &regexc, fq);
			}
			fclose(fd);
		}
	}
	else {
		calculateDirHashUtil(dir_path, include, exclude, &reginc, &regexc, fq);
	}
	
    if (strcmp(include,"")) regfree(&reginc);
    if (strcmp(exclude,"")) regfree(&regexc);
}

/*
This is the major function of the workload measurement library.
It scans the Manifest for the key words :
File Path **** Hard Dependency
Dir Path  **** Hard Dependency
DigestAlg **** Hard Dependency
Include **** Hard Dependency
Exclude **** Hard Dependency
Symlink Path **** Hard Dependency
and generates appropriate logs.

Maybe we can have a to_upper/lower kinda function here that can take care of format issues.(Not covered in the Lite version)
Manifest path is passed as the argument to the function.
Mount path is the directory where image is mounted.

How it works:
File is scanned line by line, value of file path, dir path, incl, excl cases are obtained
if its just a file or a dir, the path is passed directly to the hashing function: calculate()
If there are incl, excl cases, system command is run to create a file containing directory files of the required type
The newly created filepath (Not file object!)
is passed to calculate and the hash is added against log the dir in question
*/
int generateMeasurementLogs(FILE *fp, char *mountPath) {

	int result = 1;
	size_t len = 32768;
	int digest_check = 0;
    char *line = NULL;
    char *temp_ptr = NULL;
	char hashType[10];
	char cumulativeHash[MAX_HASH_LEN]= {'\0'};
    FILE *fq;
    
	strcpy_s(fs_mount_path,sizeof(fs_mount_path),mountPath);

	fq = fopen(measurement_file, "w");
	if (fq == NULL) {
		log_error("Can not open Measurement file: %s to write the measurements", measurement_file);
		return 0;
	}
 
	line = (char *)malloc(sizeof(char) * len);
	if (line == NULL) {
		log_error("Failed to allocate memory for reading manifest");
		fclose(fq);
		return 0;
	}
	//Read Manifest to get list of files to hash
	while (fgets(line, len, fp) != NULL) {
		log_info("Line Read : %s", line);
		if(feof(fp)) {
			log_debug("End of file found");
		    break;
		}
		
		if(strstr(line,"<?xml ") != NULL) {
			fprintf(fq,"%s", tokenizeString(line, "\n"));
		}
		
		if(strstr(line,"<Manifest ") != NULL) {
		    temp_ptr = strstr(line,"DigestAlg=");
		    if(temp_ptr != NULL){
		        /*Get the type of hash */
		        tagEntry(temp_ptr);
		        strcpy_s(hashType,sizeof(hashType),toUpperCase(node_value));
				
			digest_check = validateHashAlgorithm(hashType);
			if(!digest_check){
				log_error("Unsupported Digest Algorithm : %s", hashType);
				result = 0;
				goto final;
			}

			if (!initializeHashAlgorithm(hashType)) {
				log_error("Unable to initialize Digest Algorithm : %s", hashType);
				result = 0;
				goto final;
			}

			log_info("Type of Hash used : %s",hashType);
			log_debug("Size of Hash used : %d",cumulative_hash_len);
			replaceAllStr(line, "Manifest", "Measurement");
			replaceAllStr(line, "manifest", "measurement");
			fprintf(fq,"%s", tokenizeString(line, "\n"));
		    }
		}

		//File Hashes
		if(strstr(line,"<File Path=") != NULL && digest_check) {
		    calculateFileHash(line, fq);
		}

		//Symlink Hashes
		if(strstr(line,"<Symlink Path=") != NULL && digest_check) {
		    calculateSymlinkHash(line, fq);
		}

		//Directory Hashes
		if(strstr(line,"<Dir ") != NULL && digest_check) {
			calculateDirHash(line, fq);
		}//Dir hash ends

	}//While ends

	if (!digest_check) {
		log_error("Not able to retrieve Digest Algorithm from manifest");
		result = 0;
		goto final;
	}

	bin2hex(cumulative_hash, cumulative_hash_len, cumulativeHash, sizeof(cumulativeHash));
	log_info("Cumulative Hash : %s", cumulativeHash);
	fprintf(fq, "<CumulativeHash>%s</CumulativeHash>", cumulativeHash);
	fprintf(fq, "</Measurement>");

final:
	free(line);
	fclose(fq);
	return result;
}

char* measure(char *manifest_xml, char *mount_path) {

	char *measurement_xml = NULL;
	FILE *log_fp, *manifest_fp = NULL, *measurement_fp = NULL;

	log_fp = configure_logger();
	if (log_fp == NULL) {
		printf("Failed to configure logger\n");
		return NULL;
	}

    log_info("MANIFEST-XMl : %s", manifest_xml);
    log_info("MOUNTED-PATH : %s", mount_path);

	manifest_fp = formatManifestXml(manifest_xml, manifest_fp);
	if (manifest_fp == NULL) {
		log_error("Failed to convert inline XML to pretty print");
		fclose(log_fp);
		return NULL;
	}

	if (!generateMeasurementLogs(manifest_fp, mount_path)) {
		log_error("Failed to generate measurement logs");
		goto final;
	}
	
	measurement_fp = fopen(measurement_file, "r");
	if (measurement_fp == NULL) {
		log_error("Unable to open file : %s", measurement_file);
		goto final;
	}

	fseek(measurement_fp, 0, SEEK_END);
	int length = ftell(measurement_fp);
	fseek(measurement_fp, 0, SEEK_SET);
	
	measurement_xml = (char *)calloc(sizeof(char), length+1);
	if (measurement_xml == NULL) {
		log_error("Can't allocate memory for measurement xml");
		goto final;
	}

	fread (measurement_xml, 1, length, measurement_fp);
	log_info("MEASUREMENT-XMl : %s", measurement_xml);

final:
	fclose(log_fp);
	fclose(manifest_fp);
	if (measurement_fp) fclose(measurement_fp);
	remove(measurement_file);
	remove(temp_file);
	return measurement_xml;
}
