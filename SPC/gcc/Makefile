####################################################
#  Include Configure File                          #
####################################################
include Makefile.conf

####################################################
#  Target                                          #
####################################################
TARGET=libPAKEClient.a
TARGET_S=libPAKEClient.so

####################################################
#  Definitions                                     #
####################################################
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
CC=$(CROSS_COMPILE)gcc
CPP= $(CROSS_COMPILE)g++
RANLIB=$(CROSS_COMPILE)ranlib

LDFLAGS=-lm

STATIC_SUFFIX=.a
SHARED_SUFFIX=.so


####################################################
#  PATH Define                                     #
####################################################
# base directories
BUILD_DIR = $(CRYPTOCORE_HOME)/gcc/build
INCLUDE_DIR = $(CRYPTOCORE_HOME)/Inc
SRC_DIR = $(CRYPTOCORE_HOME)/Src

# build path
BUILD_PATH = $(BUILD_DIR)/$(PLATFORM)

####################################################
#  Source Codes                                    #
####################################################
BUILD_FILES =  base/aes.c base/ANSI_x931.c base/bignum.c base/des.c base/ecc.c base/fast_math.c base/hash.c base/md5.c base/moo.c base/pkcs1_v21.c base/rc4.c base/sha1.c base/sha2.c base/snow2.c
BUILD_FILES += middle/cmac.c middle/dh.c middle/dsa.c middle/ecdh.c middle/ecdsa.c middle/hmac.c middle/rng.c middle/rsa.c middle/symmetric.c middle/tdes.c
#BUILD_FILES += CC_API.c DRMLog.c WhiteBox/SDWAP.c WhiteBox/SDWAP_TblGen.c WhiteBox/SWAPv2.c  WhiteBox/SWAPv2_TblGen.c SAKEP.cpp SPCApi.cpp Util.cpp DtcpCTcpSocket.cpp
BUILD_FILES += CC_API.c DRMLog.c WhiteBox/SDWAP.c WhiteBox/SDWAP_TblGen.c WhiteBox/SWAPv2.c  WhiteBox/SWAPv2_TblGen.c SAKEP.cpp SPCApi.cpp Util.cpp 
####################################################
#  Includes                                        #
####################################################
BUILD_INCS = -I$(INCLUDE_DIR) -I$(INCLUDE_DIR)/middle -I$(INCLUDE_DIR)/base -I$(INCLUDE_DIR)/WhiteBox

####################################################
#  Make Options                                    #
####################################################
# Disable implicit suffix rules.
.SUFFIXES:

# Configure class-based search paths.
vpath
vpath %.c    $(SRC_DIR)
vpath %.c    $(SRC_DIR)/middle
vpath %.c    $(SRC_DIR)/base
vpath %.c    $(SRC_DIR)/WhiteBox
vpath %.cpp  $(SRC_DIR)
vpath %.o    $(BUILD_PATH)

# Filter out C object files we know how to build.
BUILD_C_OBJS := $(addsuffix .o, $(basename $(filter %.c, $(BUILD_FILES))))
BUILD_CPP_OBJS := $(addsuffix .o, $(basename $(filter %.cpp, $(BUILD_FILES))))

# Append build directory path to object files.
OBJS := $(BUILD_C_OBJS:%.o=$(BUILD_PATH)/%.o)
OBJCPP := $(BUILD_CPP_OBJS:%.o=$(BUILD_PATH)/%.o)

LDFLAGS += $(STATIC_LDFLAGS) 

all: $(BUILD_PATH)/$(TARGET)

# Build library
$(BUILD_PATH)/$(TARGET): $(OBJS) $(OBJCPP)
	@echo -- Archiving static and dynamic library SAKEP Client --
	@echo $(BUILD_PATH)/$(TARGET_S) $(BUILD_PATH)/$(TARGET)
	@mkdir -p $(dir $@)
	@$(AR) cr $@ $(OBJS) $(OBJCPP) 	
#	@$(CC) -shared -o $(BUILD_PATH)/$(TARGET_S) -Wl,--whole-archive $(BUILD_PATH)/$(TARGET) -Wl,--no-whole-archive
#	@rm -rf $(OBJS) $(OBJCPP) $(BUILD_PATH)/base $(BUILD_PATH)/middle $(BUILD_PATH)/WhiteBox 
#	@rm -rf $(OBJCPP) $(BUILD_PATH)/base $(BUILD_PATH)/middle $(BUILD_PATH)/WhiteBox $(BUILD_PATH)
	
# Compile C source
$(BUILD_PATH)/%.o: %.c
	@echo $(notdir $<)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(BUILD_INCS) -c $< -o $@ 

# Compile CPP source
$(BUILD_PATH)/%.o: %.cpp
	@echo $(notdir $<)
	@mkdir -p $(dir $@)
	$(CPP) $(CFLAGS) $(BUILD_INCS) -c $< -o $@
	
clean:
	@echo -- Clean $(SRC_NAME) -- 
	@rm -rf $(BUILD_PATH)
