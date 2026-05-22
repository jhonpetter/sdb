/*
 * SDB - Smart Development Bridge
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:
 * Ho Namkoong <ho.namkoong@samsung.com>
 * Yoonki Park <yoonki.park@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 * - S-Core Co., Ltd
 *
 */

#ifndef COMMON_MODULES_H_
#define COMMON_MODULES_H_

#include "linkedlist.h"
#include "fdevent.h"

#define MAX_PAYLOAD_V1  (4*1024)
#define MAX_PAYLOAD_V2  (256*1024)
#define MAX_PAYLOAD     MAX_PAYLOAD_V2
#define CHUNK_SIZE (64*1024)
#define DEFAULT_SDB_QEMU_PORT 26097
#define DEFAULT_SDB_PORT 26099

#define A_VERSION 0x0100000
#define SDB_VERSION_MAJOR   2       // increments upon significant architectural changes or the achievement of important milestones
#define SDB_VERSION_MINOR   3       // progress is made within a major version
#define SDB_VERSION_PATCH   2       // increments for small sets of changes

#define SDB_VERSION_MAX_LENGTH  128

extern MAP hex_map;

typedef struct adisconnect adisconnect;
typedef struct atransport atransport;
typedef struct usb_handle usb_handle;
typedef struct amessage amessage;
typedef struct apacket apacket;
#define TOKEN_SIZE 20

typedef struct amessage MESSAGE;
typedef struct apacket PACKET;
typedef struct atransport TRANSPORT;

struct message {
	unsigned command; /* command identifier constant      */
	unsigned arg0; /* first argument                   */
	unsigned arg1; /* second argument                  */
	unsigned data_length; /* length of payload (0 is allowed) */
	unsigned data_check; /* checksum of data payload         */
	unsigned magic; /* command ^ 0xffffffff             */
};

struct amessage
{
    unsigned command;       /* command identifier constant      */
    unsigned arg0;          /* first argument                   */
    unsigned arg1;          /* second argument                  */
    unsigned data_length;   /* length of payload (0 is allowed) */
    unsigned data_check;    /* checksum of data payload         */
    unsigned magic;         /* command ^ 0xffffffff             */
};

struct apacket
{
    apacket *next;

    unsigned len;
    unsigned char *ptr;

    amessage msg;
    unsigned char data[MAX_PAYLOAD];
};

struct packet {
	LIST_NODE* node;

	unsigned len;
	void *ptr;

	MESSAGE msg;
	unsigned char data[MAX_PAYLOAD];
};

typedef enum transport_type {
	kTransportUsb, kTransportLocal, kTransportAny, kTransportConnect,
//TODO REMOTE_DEVICE_CONNECT
//kTransportRemoteDevCon
} transport_type;

typedef enum platform_type {
    PLATFORM_UNKNOWN,
    PLATFORM_TIZEN,
    PLATFORM_ANDROID,
} platform_type;

#define PLATFORM_STR_UNKNOWN "unknown"
#define PLATFORM_STR_TIZEN "tizen"
#define PLATFORM_STR_ANDROID "android"

struct transport {
	LIST_NODE* node;
	//TODO REMOTE_DEVICE_CONNECT
	//list for remote sockets which wait for CNXN
	//LIST_NODE* remote_cnxn_socket;

	int (*read_from_remote)(TRANSPORT* t, void* data, int len);
	int (*write_to_remote)(PACKET *p, TRANSPORT *t);
	void (*close)(TRANSPORT *t);
	void (*kick)(TRANSPORT *t);

	int connection_state;

	//for checking emulator suspended mode
	int suspended;
	transport_type type;

	usb_handle *usb;
	int sfd;

	char *serial;
	char host[20];
	int sdb_port;
	char *device_name;

	int kicked;
	unsigned req;
	unsigned res;
};

/* the adisconnect structure is used to record a callback that
 ** will be called whenever a transport is disconnected (e.g. by the user)
 ** this should be used to cleanup objects that depend on the
 ** transport (e.g. remote sockets, listeners, etc...)
 */
struct adisconnect {
	void (*func)(void* opaque, atransport* t);
	void* opaque;
	adisconnect* next;
	adisconnect* prev;
};

struct atransport
{
    atransport *next;
    atransport *prev;

    //int (*read_from_remote)(apacket *p, atransport *t);
    int (*read_from_remote)(TRANSPORT* t, void* data, int len);

    int (*write_to_remote)(apacket *p, atransport *t);
    void (*close)(atransport *t);
    void (*kick)(atransport *t);

    int fd;
    int transport_socket;
    fdevent transport_fde;
    int ref_count;
    unsigned sync_token;
    int connection_state;
    int online;
    unsigned target_type;
    transport_type type;

        /* usb handle or socket fd as needed */
    usb_handle *usb;
    int sfd;

        /* used to identify transports for clients */
    char *serial;
    char *product;
    char *model;
    char *device;
    char *devpath;
    int adb_port; // Use for emulators (local transport)

        /* a list of adisconnect callbacks called when the transport is kicked */
    int          kicked;
    adisconnect  disconnects;

    void *key;
    unsigned char token[TOKEN_SIZE];
    fdevent auth_fde;
    unsigned failed_auth_attempts;

    int protocol_version;
    size_t max_payload;

    //sdb specific
    LIST_NODE* node;
	unsigned req;
	unsigned res;
	int sdb_port;
	int suspended;
	char host[20];
	char *device_name;

	platform_type platform;

#ifdef SUPPORT_ENCRYPT
	unsigned encryption; // flag whether this transport is on encryption, 0 = no-encryption / 1 = encryption
	int sessionID; // session id for encryption, key of encryption map
#endif
};


typedef enum listener_type {
	serverListener, qemuListener, forwardListener
} LISTENER_TYPE;

typedef struct listener LISTENER;
struct listener {
	LIST_NODE* node;

	FD_EVENT fde;
	int fd;

	int local_port;
	int connect_port;
	const char *connect_to;
	TRANSPORT *transport;
	LISTENER_TYPE type;
};

typedef struct t_packet T_PACKET;
struct t_packet {
	TRANSPORT* t;
	PACKET* p;
};

typedef struct socket SDB_SOCKET;
struct socket {
	int status;
	LIST_NODE* node;

	unsigned local_id;
	unsigned remote_id;

	int closing;
	FD_EVENT fde;
	int fd;

	LIST_NODE* pkt_list;
	TRANSPORT *transport;

	PACKET* read_packet;
};

int readx(int fd, void *ptr, size_t len);
int writex(int fd, const void *ptr, size_t len);
int notify_qemu(char* host, int port, char* serial);

#endif /* SDB_TYPES_H_ */
