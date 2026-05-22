#
#
# Makefile for sdb
#

#
HOST_OS := $(shell uname -s | tr A-Z a-z | cut -d'_' -f1)
LBITS := $(shell getconf LONG_BIT)
BINDIR := ./bin
INSTALLDIR := usr/bin
MODULE := sdb

ENCLIB := spc
ENCLIB_BUILD_PATH := ./SPC/gcc
ENCLIB_CFLAGS := -I./SPC/Inc
ENCLIB_LFLAGS := ./SPC/gcc/build/linux/libPAKEClient.a

# sdb host tool
# =========================================================

ifeq ($(HOST_OS),darwin)
	CC := clang
	CXX := clang++
endif
#
ifeq ($(HOST_OS),linux)
	LOCAL_USB_SRC :=  src/usb_linux.c
	LOCAL_UTIL_SRC := src/utils_unix.c
	LOCAL_OTHER_SRC := src/fdevent.c src/fdevent_unix.c src/auto_complete.c
	LOCAL_LFLAGS := -lrt -lpthread -lcrypto
	LOCAL_CFLAGS := -DOS_LINUX -DHAVE_FORKEXEC -DHAVE_SYMLINKS -DSDB_HOST=1 -DSDB_HOST_ON_TARGET=1 -D_FILE_OFFSET_BITS=64
endif

ifeq ($(HOST_OS),darwin)
	LOCAL_USB_SRC := src/usb_darwin.c src/device_vendors.c
	LOCAL_UTIL_SRC := src/utils_unix.c
	LOCAL_OTHER_SRC := src/fdevent.c src/fdevent_unix.c src/auto_complete.c
	LOCAL_LFLAGS := -stdlib=libstdc++ -lpthread -lcrypto -framework CoreFoundation -framework IOKit -framework Carbon
	LOCAL_CFLAGS := -DOS_DARWIN -DHAVE_FORKEXEC -DHAVE_SYMLINKS -mmacosx-version-min=10.4 -DSDB_HOST=1 -DSDB_HOST_ON_TARGET=1
endif

ifeq ($(HOST_OS),mingw32)
	LOCAL_USB_SRC := src/usb_windows.c
	LOCAL_UTIL_SRC := src/utils_windows.c
	LOCAL_OTHER_SRC := src/fdevent.c  src/fdevent_windows.c src/sysdeps_win32.c
	LOCAL_CFLAGS := -DOS_WINDOWS
	LOCAL_IFLAGS := -I/mingw/include/ddk
	LOCAL_LFLAGS := -lws2_32 ./lib/libcrypto.a -lgdi32
	LOCAL_STATIC_LFLAGS := -static-libgcc -static-libstdc++ /mingw/lib/libsetupapi.a
endif


SDB_SRC_CFILES := \
	src/sdb.c \
	src/transport.c \
	src/transport_local.c \
	src/transport_usb.c \
	src/commandline.c \
	src/sdb_client.c \
	src/sockets.c \
	src/file_sync_client.c \
	$(LOCAL_USB_SRC) \
	$(LOCAL_UTIL_SRC) \
	$(LOCAL_OTHER_SRC) \
	src/utils.c \
	src/strutils.c \
	src/memutils.c \
	src/linkedlist.c \
	src/sdb_model.c \
	src/sdb_constants.c \
	src/file_sync_functions.c \
	src/command_function.c \
	src/log.c \
	src/listener.c \
	src/sdb_map.c \
	src/sdb_messages.c \
	src/adb_auth_host.c
	
SDB_SRC_CPPFILES := \
	src/encryption.cpp \
	src/SPCManager.cpp

SDB_CFLAGS := -O2 -g -Wall -Wno-unused-parameter
SDB_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
SDB_CFLAGS += -DSUPPORT_ENCRYPT
SDB_CFLAGS += -Iinclude -Isrc
SDB_CFLAGS += $(LOCAL_CFLAGS)
SDB_CFLAGS += $(ENCLIB_CFLAGS)

ifeq ($(MAKE_DEBUG),true)
SDB_CFLAGS += -DMAKE_DEBUG
endif
SDB_LFLAGS := $(LOCAL_LFLAGS)
SDB_LFLAGS += $(ENCLIB_LFLAGS)
STATIC_LFLAGS := $(LOCAL_STATIC_LFLAGS)

OBJS=${SDB_SRC_CFILES:%.c=%.o} ${SDB_SRC_CPPFILES:%.cpp=%.o}

%.o : %.c
	@echo "<<< ${<F}"	
	@$(CC) $(SDB_CFLAGS) $(LOCAL_IFLAGS) -c -o $@ $<

%.o : %.cpp
	@echo "<<< ${<F}"	
	@$(CXX) $(SDB_CFLAGS) $(LOCAL_IFLAGS) -c -o $@ $<

all : $(MODULE)

$(ENCLIB) :
	@echo "[[[ $@ ]]]"

$(MODULE) : $(OBJS)
	@echo ">>> $(ENCLIB)"
	$(MAKE) -C $(ENCLIB_BUILD_PATH)

	@echo ">>> $@"
	@mkdir -p $(BINDIR)	
	$(CXX) -o $(BINDIR)/$@ $^ $(SDB_LFLAGS) $(STATIC_LFLAGS)

install :
	mkdir -p $(DESTDIR)/$(INSTALLDIR)
	install $(BINDIR)/$(MODULE) $(DESTDIR)/$(INSTALLDIR)/$(MODULE)

clean :
	$(MAKE) -C $(ENCLIB_BUILD_PATH) clean
	rm -rf src/*.o
	rm -rf $(BINDIR)
	rm -rf src/*.gcda
	rm -rf src/*.gcno
	rm -rf src/*.gcov
	
