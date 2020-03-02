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

TPMEXT_ROOT=../..
BIN=$(TPMEXT_ROOT)/bin
OBJ=$(TPMEXT_ROOT)/build/tpmextendobjects
SAFESTRING=../SafeStringLibrary/
SAFESTRING_INCLUDE=$(SAFESTRING)/include/

# compiler flags:
LDFLAGS  = -pie -z noexecstack -z relro -z now
CFLAGS = -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D FORTIFY_SOURCE=2 $(DEBUG_CFLAGS)

LIBS  = -lSafeStringRelease
CURR_DIR  = `pwd`

INCLUDES  = -I$(CURR_DIR) -I$(SAFESTRING_INCLUDE)

OBJS  = $(OBJ)/tpmextend.o $(OBJ)/tpm.o $(OBJ)/tpm2.o

# the build target executable:
TARGET  = tpmextend

all: $(BIN)/$(TARGET)

$(BIN)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -L$(SAFESTRING) $(LIBS) -o $(BIN)/$(TARGET)

$(OBJ)/tpmextend.o: tpmextend.c
	$(CC) $(CFLAGS) $(CURR_DIR)/tpmextend.c $(INCLUDES) -c -o $(OBJ)/tpmextend.o  

$(OBJ)/tpm.o: tpm.c tpm.h
	$(CC) $(CFLAGS) $(CURR_DIR)/tpm.c  $(INCLUDES) -c -o $(OBJ)/tpm.o

$(OBJ)/tpm2.o: tpm2.c tpm2.h
	$(CC) $(CFLAGS) $(CURR_DIR)/tpm2.c  $(INCLUDES) -c -o $(OBJ)/tpm2.o

