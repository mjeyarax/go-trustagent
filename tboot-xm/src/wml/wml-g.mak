# /*
# Copyright (C) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
# */

# the compiler: gcc for C program
CC = gcc

ifeq ($(debug),1)
    DEBUG_CFLAGS     := -Wall  -Wno-format -g -DDEBUG
else
    DEBUG_CFLAGS     := -Wall -Wno-unknown-pragmas -Wno-format -O3 -Wformat -Wformat-security
endif

WML_ROOT=../..
BIN=$(WML_ROOT)/bin
LIB=$(WML_ROOT)/lib
OBJ=$(WML_ROOT)/build/wmlobjects
SAFESTRING=../SafeStringLibrary/
SAFESTRING_INCLUDE=$(SAFESTRING)/include/
#LIBXML_INCLUDE=/usr/include/libxml2/

# compiler flags:
LDFLAGS  = -z noexecstack -z relro -z now
CFLAGS = -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIC -fstack-protector-strong -O2 -D FORTIFY_SOURCE=2 $(DEBUG_CFLAGS)

#LIBS  = -lxml2 -lcrypto -lSafeStringRelease
LIBS  = -lcrypto -lSafeStringRelease
CURR_DIR  = `pwd`

#INCLUDES  = -I$(CURR_DIR) -I$(SAFESTRING_INCLUDE) -I$(LIBXML_INCLUDE)
INCLUDES  = -I$(CURR_DIR) -I$(SAFESTRING_INCLUDE)
OBJS  = $(OBJ)/measurement.o $(OBJ)/char_converter.o \
		$(OBJ)/xml_formatter.o $(OBJ)/logging.o \
		$(OBJ)/crypt.o $(OBJ)/util.o $(OBJ)/log.o

# the build target executable:
TARGET  = libwml.so

all: $(LIB)/$(TARGET)

$(LIB)/$(TARGET): $(OBJS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) $(OBJS) -L$(SAFESTRING) $(LIBS) -o $(LIB)/$(TARGET)
ifneq "$(debug)" "1"
	strip -s $(LIB)/$(TARGET)
endif

$(OBJ)/measurement.o: measurement.c measurement.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/measurement.o $(CURR_DIR)/measurement.c

$(OBJ)/char_converter.o: char_converter.c char_converter.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/char_converter.o $(CURR_DIR)/char_converter.c

$(OBJ)/xml_formatter.o: xml_formatter.c xml_formatter.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/xml_formatter.o $(CURR_DIR)/xml_formatter.c

$(OBJ)/logging.o: logging.c logging.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/logging.o $(CURR_DIR)/logging.c

$(OBJ)/crypt.o: crypt.c crypt.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/crypt.o $(CURR_DIR)/crypt.c

$(OBJ)/util.o: util.c util.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/util.o $(CURR_DIR)/util.c

$(OBJ)/log.o: log.c log.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/log.o $(CURR_DIR)/log.c

