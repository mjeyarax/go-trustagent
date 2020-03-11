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
OBJ=$(WML_ROOT)/build/measureobjects
SAFESTRING=../SafeStringLibrary/
WML_INCLUDE=../wml/

# compiler flags:
LDFLAGS  = -pie -z noexecstack -z relro -z now
CFLAGS = -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D FORTIFY_SOURCE=2 $(DEBUG_CFLAGS)

LIBS  = -lwml -lSafeStringRelease

CURR_DIR  = `pwd`

INCLUDES  = -I$(CURR_DIR) -I$(WML_INCLUDE) 

OBJS  = $(OBJ)/measure.o

# the build target executable:
TARGET  = measure

all: $(BIN)/$(TARGET)

$(BIN)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -L$(LIB) -L$(SAFESTRING) $(LIBS) -o $(BIN)/$(TARGET)
ifneq "$(debug)" "1"
	strip -s $(BIN)/$(TARGET)
endif

$(OBJ)/measure.o: measure.c
	$(CC) $(CFLAGS) $(CURR_DIR)/measure.c  $(INCLUDES) -c -o $(OBJ)/measure.o

