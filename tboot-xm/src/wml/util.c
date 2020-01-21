/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * util.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include <dirent.h>
#include <unistd.h>

#include "common.h"
#include "crypt.h"
#include "util.h"

/*
* getSymLinkValue:
* @path : path of the file/symbolic link
*
* Returns the actual value for the symbolic link provided as input
*/
int getSymLinkValue(char *path) {
	char symlinkpath[512];
    char sympathroot[512];
    struct stat statbuf;
    if (lstat(path, &statbuf) == -1) {  /* if error occured */
        log_error("Not a valid path - %s", path);
        return -1;
    }

    // Check if the file path is a symbolic link
    if (S_ISLNK(statbuf.st_mode) == 1) {
        // If symbolic link doesn't exists read the path its pointing to
        int len = readlink(path, symlinkpath, sizeof(symlinkpath));
        if (len != -1) {
            symlinkpath[len] = '\0';
        }
        log_debug("Symlink %s points to %s", path, symlinkpath);

        // If the path is starting with "/" and 'fs_mount_path' is not appended
        if(((strstr(symlinkpath, "/") - symlinkpath) == 0) && (strstr(symlinkpath,fs_mount_path) == NULL)) {
            if(snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, symlinkpath) > 0 ) {
            	log_debug("Absolute symlink path %s points to %s", symlinkpath, sympathroot);
			}
        }
        else {
            char* last_backslash = strrchr(path, '/');
            if (last_backslash) {
                *last_backslash = '\0';
            }
            if (snprintf(sympathroot, sizeof sympathroot, "%s%s%s", path, "/", symlinkpath) > 0) {
	            log_debug("Relative symlink path %s points to %s", symlinkpath, sympathroot);
			}
        }
        strcpy_s(path, MAX_LEN, symlinkpath);
    }
	else {
		log_error("Not a valid Symlink - %s", path);
		return -1;
	}
    return 0;
}

char *toUpperCase(char *str) {

	char *temp = str;
	while (*temp) {
		if (*temp >= 97 && *temp <= 122)
			*temp -= 32;
		temp++;
	}
	return str;
}

void replaceAllStr(char * orig_str, char * search_str, char * replace_str) {

      //a buffer variable to do all replace things
      char buffer[NODE_LEN];
      //to store the pointer returned from strstr
      char * ch;

      //first exit condition
      if(!(ch = strstr(orig_str, search_str)))
              return;

      //copy all the content to buffer before the first occurrence of the search string
      strncpy_s(buffer, sizeof(buffer), orig_str, ch-orig_str);

      //prepare the buffer for appending by adding a null to the end of it
      buffer[ch-orig_str] = 0;

      //append using snprintf function
      snprintf(buffer + (ch - orig_str), sizeof(buffer), "%s%s", replace_str, ch + strnlen_s(search_str, NODE_LEN));

      //empty orig_str for copying
      orig_str[0] = 0;
      strcpy_s(orig_str, MAX_LEN, buffer);

      //pass recursively to replace other occurrences
      return replaceAllStr(orig_str, search_str, replace_str);
}

/*
Check if file exist on file system or not.
return 0 if file exist, non zero if file does not exist or can't be found
*/
int doesFileExist(char * filename) {
	struct stat info;
	if (stat(filename, &info)) {
		log_error("Not a valid path - %s", filename);
		return -1;
	}
	return 0;
}

/*
Check if directory exist on file system or not.
return 0 if directory exist, non zero if directory does not exist or can't be found
*/
int doesDirExist(char * dirname) {
	struct stat info;
	if (stat(dirname, &info)) {
		log_error("Not a valid path - %s", dirname);
		return -1;
	}
	else if (!(info.st_mode & S_IFDIR)) {
		log_error("Not a valid directory - %s", dirname);
		return -1;
	}
	return 0;
}

/*This function returns the value of an XML tag. 
Input parameter: Line read from the XML file
Output: Value in the tag
How it works: THe function accepts a line containing tag value as input
it parses the line until it reaches quotes (" ") 
and returns the value held inside them 
so <File Path = "a.txt" .....> returns a.txt
include="*.out" ....> returns *.out and so on..
*/
void tagEntry (char* line) {

    int i =0;
    char key[NODE_LEN];
    char *start,*end;
    /*We use a local string 'key' here so that we dont make any changes
    to the line pointer passed to the function. 
    This is useful in a line containing more than 1 XML tag values.
    E.g :<Dir Path="/etc" include="*.bin" exclude="*.conf">
    */
    strcpy_s(key,sizeof(key),line);
 
    while(key[i] != '\"')
        i++;
    start = &key[++i];

    end = start;
    while(*end != '\"')
        end++;
    *end = '\0';

    strcpy_s(node_value, sizeof(node_value), start);
}

void convertWildcardToRegex(char *wildcard) {

    int i=0, j=0;
    char c;
    char key[NODE_LEN];

    strcpy_s(key,sizeof(key),wildcard);
    node_value[j++] = '^';

    c = key[i];
    while(c) {
    	switch(c) {
      	    case '*':
		node_value[j++] = '.';
        	node_value[j++] = '*';
        	break;
            case '?':
        	node_value[j++] = '.';
        	break;
      	    case '(':
      	    case ')':
      	    case '[':
      	    case ']':
      	    case '$':
     	    case '^':
      	    case '.':
      	    case '{':
      	    case '}':
      	    case '|':
      	    case '\\':
        	node_value[j++] = '\\';
        	node_value[j++] = c;
        	break;
      	    default:
        	node_value[j++] = c;
        	break;
	}
	c = key[++i];
    }

    node_value[j++] = '$';
    node_value[j] = '\0';
}

char *getTagValue(char *line, char *key) {

	char *temp_ptr = NULL;
	temp_ptr = strstr(line, key);
	if (temp_ptr != NULL ) {
		tagEntry(temp_ptr);
		return node_value;
    }
	return temp_ptr;
}

char *tokenizeString(char *line, char *delim) {

	size_t dhash_max = 128;
    char *dhash = NULL;
	char *next_token = NULL;
	
	strcpy_s(node_value,NODE_LEN,line);
	dhash = node_value;
	dhash_max = strnlen_s(node_value, NODE_LEN);
	strtok_s(dhash,&dhash_max,delim,&next_token);

	return dhash;
}

int walkDirRecurse(const char *dir_path, const char *include, const char *exclude, regex_t *reginc, regex_t *regexc, FILE *fd, int spec) {

    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;

    int flag;
    char file_name[FILENAME_MAX];
    char file_path[FILENAME_MAX];

    int len = strnlen_s(dir_path, MAX_LEN);
    if (len >= FILENAME_MAX - 1) {
        log_error("Filename too long: %s", dir_path);
        return -1;
    }

    strcpy_s(file_path, FILENAME_MAX, dir_path);
    file_path[len++] = '/';

    if(!(dir = opendir(dir_path))) {
        log_error("Cannot open directory: %s", dir_path);
        return -1;
    }

    while((entry = readdir(dir))) {

        strcpy_s(file_path + len, FILENAME_MAX - len, entry->d_name);
        if (lstat(file_path, &statbuf) == -1) {
            log_warn("Not a valid path - %s", file_path);
            continue;
        }

        if(S_ISDIR(statbuf.st_mode)) {
            // Found a directory, but ignore . and ..
            if(!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name))
                continue;

            // Recurse at a new directory level
            walkDirRecurse(file_path, include, exclude, reginc, regexc, fd, spec);

            if (!(spec & WS_DIRS))
                continue;
        }
        else if (S_ISREG(statbuf.st_mode) && !(spec & WS_FILES))
            continue;
        else if (S_ISLNK(statbuf.st_mode) && !(spec & WS_LINK))
            continue;

        if ((spec & WS_FILES) && (spec & WS_LINK)) {
            strcpy_s(file_name, sizeof(file_name), entry->d_name);
        }
        else {
            strcpy_s(file_name, sizeof(file_name), file_path + strnlen_s(fs_mount_path, sizeof(fs_mount_path)));
        }

        flag = include? !regexec(reginc, file_name, 0, 0, 0): 1;
        if (flag) {
            flag = exclude? regexec(regexc, file_name, 0, 0, 0): 1;
            if (flag) {
                log_debug("Found Match : %s", file_name);
				fprintf(fd, "%s\n", file_name);
            }
        }
    }
    closedir(dir);

    return 0;
}

FILE *getMatchingEntries(char *line, FILE *fd, int spec) {

	FILE *file;
	regex_t reg;
	int retVal = -1;
	char *last_oblique_ptr = NULL;
	char bPath[NODE_LEN] = {'\0'};
	char sPath[NODE_LEN] = {'\0'};

	strcpy_s(sPath,sizeof(sPath),fs_mount_path);
    strcat_s(sPath,sizeof(sPath),tokenizeString(line, ".*"));//path in the VM
	
	last_oblique_ptr = strrchr(sPath,'/');
	strncpy_s(bPath, sizeof(bPath), sPath, strnlen_s(sPath, sizeof(sPath))-strnlen_s(last_oblique_ptr,sizeof(sPath)));

	if (regcomp(&reg, line, REG_EXTENDED | REG_NOSUB)) {
		log_warn("Not a valid regex. Skipping measurement...");
		return NULL;
	}

	file = fopen(temp_file, "w");
	if (file == NULL) {
		log_error("Can not open temp file: %s for writing matched entries", temp_file);
		goto final;
	}

	retVal = walkDirRecurse(bPath, line, NULL, &reg, NULL, file, spec);
	fclose(file);
	if (retVal == 0) {
		fd = fopen(temp_file, "r");
		if (fd == NULL) {
			log_error("Cannot open temp file: %s for reading matched entries", temp_file);
			goto final;
		}
	}

final:
	regfree(&reg);
	return fd;
}

int generateDirHash(char *output, char *dir_path, char *include, char *exclude, regex_t *reginc, regex_t *regexc) {

	FILE *file;
	int retVal = -1;

	file = fopen(temp_file, "w");
	if (file == NULL) {
		log_error("Can not open temp file: %s for writing files list", temp_file);
		return -1;
	}

	retVal = walkDirRecurse(dir_path, include, exclude, reginc, regexc, file, WS_FILES|WS_LINK);
	fclose(file);
	if (retVal == 0) {
		file = fopen(temp_file, "rb");
		if (file == NULL) {
			log_error("Cannot open temp file: %s for reading files list", temp_file);
			return -1;
		}

		generateFileHash(output, file);
		fclose(file);
	}
	return retVal;
}

void calculateDirHashUtil(char *dir_path, char *include, char *exclude, regex_t *reginc, regex_t *regexc, FILE *fq) {

	int retval = -1;
	char dir_name_buff[NODE_LEN] = {'\0'};
	char output[MAX_HASH_LEN] = {'\0'};
	
	snprintf(dir_name_buff, sizeof(dir_name_buff), "%s%s", fs_mount_path, dir_path);
	log_debug("dir path : %s", dir_name_buff);
	retval = doesDirExist(dir_name_buff);
	if (retval == 0) {
		log_info("Mounted dir path for dir %s is %s", dir_path, dir_name_buff);

		/*How the process works: 
		1. Open the dir pointed by dir_name_buff
		2. Read the dir contents one by one recursively
		3. Pass those to SHA function.(Output to char output passed to the function)
		4. Return the Output string.
		*/
		retval = generateDirHash(output, dir_name_buff, strcmp(include, "")?include:NULL, strcmp(exclude, "")?exclude:NULL, reginc, regexc);
		if (retval == -1) {
			log_error("Failed to walk dir recursively: %s", dir_name_buff);
			return;
		}

		fprintf(fq, "<Dir Exclude=\"%s\" Include=\"%s\" Path=\"%s\">", exclude, include, dir_path);
		fprintf(fq, "%s</Dir>", output);
		log_info("Dir : %s Hash Measured : %s", dir_path, output);
	}
}

void calculateFileHashUtil(char *file_path, FILE *fq) {

	int retval = -1;
	char file_name_buff[NODE_LEN] = {'\0'};
	char output[MAX_HASH_LEN] = {'\0'};
	FILE *file;
	
	snprintf(file_name_buff, sizeof(file_name_buff), "%s%s", fs_mount_path, file_path);
    log_debug("file path : %s",file_name_buff);
    retval = doesFileExist(file_name_buff);
    if( retval == 0 ) {
		log_info("Mounted file path for file %s is %s",file_path,file_name_buff);
   
	    /*How the process works: 
        1. Open the file pointed by file_name_buff
        2. Read the file contents into char * buffer
        3. Pass those to SHA function.(Output to char output passed to the function)
        4. Return the Output string.
        */
	    file = fopen(file_name_buff, "rb");
		if (file == NULL) {
			log_error("Cannot open file: %s",file_name_buff);
			return;
		}

		generateFileHash(output, file);
		fclose(file);

		fprintf(fq,"<File Path=\"%s\">",file_path);
		fprintf(fq,"%s</File>", output);
		log_info("File : %s Hash Measured : %s",file_path,output);
    }
}

void calculateSymlinkHashUtil(char *sym_path, FILE *fq) {

	int retval = -1;
	char hash_str[MAX_LEN] = {'\0'};
	char file_name_buff[NODE_LEN] = {'\0'};
	char output[MAX_HASH_LEN] = {'\0'};
	
	snprintf(file_name_buff, sizeof(file_name_buff), "%s%s", fs_mount_path, sym_path);
    log_debug("symlink path : %s", file_name_buff);
    retval = getSymLinkValue(file_name_buff);
    if( retval == 0 ) {
        log_info("Target file path for symlink %s is %s",sym_path,file_name_buff);

        /*How the process works:
        1. Concatenate source path and target path
        2. Store that content into char * buffer
        3. Pass those to SHA function.(Output to char output passed to the function)
        4. Return the Output string.
        */
		snprintf(hash_str, MAX_LEN, "%s%s", sym_path, file_name_buff);
		generateStrHash(output, hash_str);
		
		fprintf(fq,"<Symlink Path=\"%s\">",sym_path);
		fprintf(fq,"%s</Symlink>", output);
        log_info("Symlink : %s Hash Measured : %s",sym_path,output);
    }
}
