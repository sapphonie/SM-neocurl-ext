# (C)2004-2008 SourceMod Development Team
# Makefile written by David "BAILOPAN" Anderson

#SMSDK = ../..
SMSDK = ../build/sm-1.11
# SRCDS_BASE = ~/srcds
# MMSOURCE17 = ../../../mmsource-central
MMSOURCE17 = ../build/mm-1.11

#####################################
### EDIT BELOW FOR OTHER PROJECTS ###
#####################################

PROJECT = curl

#Uncomment for Metamod: Source enabled extension
USEMETA = false

OBJECTS = \
	sdk/smsdk_ext.cpp 	\
	extension.cpp 		\
	curlmanager.cpp		\
	curlthread.cpp 		\
	natives.cpp 		\
	opensslmanager.cpp 	\
	opensslthread.cpp

##############################################
### CONFIGURE ANY OTHER FLAGS/OPTIONS HERE ###
##############################################

C_OPT_FLAGS = -DNDEBUG -O3 -funroll-loops -pipe -fno-strict-aliasing -g -ggdb
C_DEBUG_FLAGS = -D_DEBUG -DDEBUG
C_GCC4_FLAGS = -fvisibility=hidden
CPP_GCC4_FLAGS = -fvisibility-inlines-hidden
CPP = gcc


METAMOD = $(MMSOURCE17)/core-legacy

# yes yes i know i will clean it up later
INCLUDE += -I. -I.. -Isdk -I../ \
	-I$(MMSOURCE17)/core/sourcehook \
	-I$(SMSDK)/public \
	-I$(SMSDK)/public/extensions \
	-I$(SMSDK)/sourcepawn/include \
	-I$(SMSDK)/sourcepawn \
	-I$(SMSDK)/public/amtl/amtl \
	-I$(SMSDK)/public/amtl/ \
	-I/opt/Source/lib/openssl/include
# ../alliedmodders/mmsource-1.12
# 	-I$(METAMOD)/sourcehook \

#	-I$(SMSDK)/public/sourcepawn \


CFLAGS += -DSE_EPISODEONE=1 -DSE_DARKMESSIAH=2 -DSE_ORANGEBOX=3 -DSE_ORANGEBOXVALVE=4 -DSE_LEFT4DEAD=5 -DSE_LEFT4DEAD2=6

CFLAGS += -DCURL_STATIC_LIB

LINK += -L./lib -lcurl -lrt -lssh2 -lssl -lcrypto -lz -lnghttp2 -lngtcp2 -lbrotlidec-static -lbrotlienc-static -lbrotlicommon-static -lzstd -lgsasl
LINK += -m32 -ldl -lm -L/usr/lib32 -lstdc++
# -static


# #-lgsasl
 

CFLAGS += -D_LINUX -Dstricmp=strcasecmp -D_stricmp=strcasecmp -D_strnicmp=strncasecmp -Dstrnicmp=strncasecmp \
	-D_snprintf=snprintf -D_vsnprintf=vsnprintf -D_alloca=alloca -Dstrcmpi=strcasecmp -Wall -Wno-switch \
	-Wno-unused -mfpmath=sse -msse -DSOURCEMOD_BUILD -DHAVE_STDINT_H -m32


# 	-D_snprintf=snprintf -D_vsnprintf=vsnprintf -D_alloca=alloca -Dstrcmpi=strcasecmp -Wall -Werror -Wno-switch \


#CPPFLAGS += -Wno-non-virtual-dtor -fno-exceptions -fno-rtti -fno-threadsafe-statics
CPPFLAGS += -fno-exceptions -fno-rtti -fno-threadsafe-statics 
#-fabi-compat-version=3

################################################
### DO NOT EDIT BELOW HERE FOR MOST PROJECTS ###
################################################

ifeq "$(DEBUG)" "true"
	BIN_DIR = Debug
	CFLAGS += $(C_DEBUG_FLAGS)
else
	BIN_DIR = Release
	CFLAGS += $(C_OPT_FLAGS)
endif

ifeq "$(USEMETA)" "true"
	BIN_DIR := $(BIN_DIR).$(ENGINE)
endif

OS := $(shell uname -s)
ifeq "$(OS)" "Darwin"
	LINK += -dynamiclib
	BINARY = $(PROJECT).ext.dylib
else
	LINK += -static-libgcc -shared
	BINARY = $(PROJECT).ext.so
endif

GCC_VERSION := $(shell $(CPP) -dumpversion >&1 | cut -b1)
ifeq "$(GCC_VERSION)" "4"
	CFLAGS += $(C_GCC4_FLAGS)
	CPPFLAGS += $(CPP_GCC4_FLAGS)
endif

OBJ_LINUX := $(OBJECTS:%.cpp=$(BIN_DIR)/%.o)

$(BIN_DIR)/%.o: %.cpp
	$(CPP) $(INCLUDE) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

all: check
	mkdir -p $(BIN_DIR)/sdk

	$(MAKE) -f Makefile extension

check:
	

extension: check $(OBJ_LINUX)
	$(CPP) $(INCLUDE) $(OBJ_LINUX) $(LINK) -o $(BIN_DIR)/$(BINARY)

debug:
	$(MAKE) -f Makefile all DEBUG=true

default: all

clean: check
	rm -rf $(BIN_DIR)/*.o
	rm -rf $(BIN_DIR)/sdk/*.o
	rm -rf $(BIN_DIR)/$(BINARY)
