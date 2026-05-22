/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <assert.h>

#define  TRACE_TAG  TRACE_SDB

#include "fdevent.h"
#include "strutils.h"

#if defined(OS_LINUX) || defined(OS_DARWIN) // for UNIX
#include <termios.h>
#include <sys/ioctl.h>
#endif
#include "utils.h"
#include "sdb_client.h"
#include "file_sync_service.h"
#include "log.h"

#include "linkedlist.h"
#include "sdb_constants.h"
#include "sdb_model.h"
#include "commandline.h"
#include "command_function.h"
#include "sdb_messages.h"

static void print_help(LIST_NODE* optlist, LIST_NODE* cmdlist);
static void create_opt_list(LIST_NODE** opt_list);
static void create_cmd_list(LIST_NODE** cmd_list);
static int do_cmd(transport_type ttype, char* serial, char *cmd, ...);
static void sync_winsz(void);

struct sdb_stdin_info g_stdin_info;

#define INFOBUF_MAXLEN 64
typedef struct platform_info {
    char platform_info_version[INFOBUF_MAXLEN];
    char model_name[INFOBUF_MAXLEN]; // Emulator
    char platform_name[INFOBUF_MAXLEN]; // Tizen
    char platform_version[INFOBUF_MAXLEN]; // 2.2.1
    char profile_name[INFOBUF_MAXLEN]; // 2.2.1
} pinfo;

int get_platform_version(struct sdb_version *pversion) {
    struct platform_info pinfo;
    const char* GET_SYSTEM_INFO_CMD = "sysinfo:";
    int fd = -1;
    int ret = -1;

    if (pversion == NULL) {
        return -1;
    }

    fd = sdb_connect(GET_SYSTEM_INFO_CMD);
    if(fd < 0) {
        D("sysinfo get failed\n");
        return -1;
    }

    if (readx(fd, &pinfo, sizeof(struct platform_info)) == 0) {
        int major = 0;
        int minor = 0;
        int patch = 0;

        D("Returned platform version %s\n", pinfo.platform_version);
        ret = sscanf(pinfo.platform_version, "%d.%d.%d", &major, &minor, &patch);
        if (ret == 3) {
            pversion->major = major;
            pversion->minor = minor;
            pversion->patch = patch;
            ret = 0;
        } else if (ret == 2) {
            pversion->major = major;
            pversion->minor = minor;
            pversion->patch = 0;
            ret = 0;
        }
    }
    D("Platform version : %d.%d.%d\n", pversion->major, pversion->minor, pversion->patch);

    sdb_close(fd);
    return ret;
}

void read_and_dump(int fd)
{
    char buf[PATH_MAX];
    int len;

    while(fd >= 0) {
        D("read_and_dump(): pre sdb_read(fd=%d)\n", fd);
        len = sdb_read(fd, buf, PATH_MAX);
        D("read_and_dump(): post sdb_read(fd=%d): len=%d\n", fd, len);
        if(len == 0) {
            break;
        }

        if(len < 0) {
            if(errno == EINTR) continue;
            break;
        }
        fwrite(buf, 1, len, stdout);
        fflush(stdout);
    }

}

// TODO: move the following functions to util file for each OS.
void sdb_shell_stdin_init(int fd);
void sdb_shell_stdin_restore(int fd);
void *stdin_read_thread(void *args);
int get_screensize(int* lines, int* columns);

#if defined(OS_WINDOWS) // for Windows
HANDLE g_input_handle = NULL;
DWORD g_console_mode_save = NULL;

static char arrow_up[3] = {27, 91, 65};
static char arrow_down[3] = {27, 91, 66};
static char arrow_right[3] = {27, 91, 67};
static char arrow_left[3] = {27, 91, 68};

void sdb_shell_stdin_init(int fd)
{
    if (fd != INPUT_FD) {
        return;
    }

    g_input_handle = GetStdHandle(STD_INPUT_HANDLE);

    if(g_input_handle == INVALID_HANDLE_VALUE) {
        D("error: fail to get the stdin handle\n");
        g_input_handle = NULL;
        return;
    }

    if(!GetConsoleMode(g_input_handle, &g_console_mode_save)) {
        D("error: fail to get the stdin console mode\n");
        g_input_handle = NULL;
        return;
    }

    if(!SetConsoleMode(g_input_handle, ENABLE_MOUSE_INPUT)) {
        D("error: fail to set console mode\n");
        return;
    }
}

void sdb_shell_stdin_restore(int fd)
{
    if (fd != INPUT_FD) {
        return;
    }

    if (g_input_handle != NULL) {
        if(!SetConsoleMode(g_input_handle, g_console_mode_save)) {
            D("error: fail to restore console mode\n");
        }
        g_input_handle = NULL;
    }
}

void *stdin_read_thread(void *args)
{
    char* buf = NULL;
    int buf_len;
    INPUT_RECORD i_record;
    DWORD cNumRead;

    if(g_console_mode_save != NULL) {
        while(1) {
            if(!ReadConsoleInput(g_input_handle, &i_record, 1, &cNumRead)) {
                D("error: fail to read console standard input\n");
                break;
            }

            if(i_record.EventType == KEY_EVENT) {
                KEY_EVENT_RECORD* event = &(i_record.Event.KeyEvent);

                if(event->bKeyDown) {
                    if(event->uChar.AsciiChar) {
                        buf = &(event->uChar.AsciiChar);
                        buf_len = 1;
                    }
                    else {
                        buf_len = 3;
                        switch (event->wVirtualKeyCode) {
                            //arrow up
                            case 0x26:
                                buf = arrow_up;
                                break;
                            //arrow down
                            case 0x28:
                                buf = arrow_down;
                                break;
                            //arrow left
                            case 0x25:
                                buf = arrow_left;
                                break;
                            //arrow right
                            case 0x27:
                                buf = arrow_right;
                                break;
                        }
                    }
                    if(buf) {
                        if(sdb_write(g_stdin_info.remote_fd, buf, buf_len) <= 0) {
                            break;
                        }
                    }
                    buf = NULL;
                }
            } else if(i_record.EventType == MOUSE_EVENT) {
                if (i_record.Event.MouseEvent.dwEventFlags == 0) {
                    if (g_stdin_info.enable_sync_winsz == SYNCWINSZ_SUPPORTED) {
                        sync_winsz();
                    }
                }
            }
        }
    }
    else {
        while(1) {
            unsigned char buf[1024];
            int r = unix_read(g_stdin_info.stdin_fd, buf, 1024);
            if(r == 0) break;
            if(r < 0) {
                if(errno == EINTR) continue;
                break;
            }
            r = sdb_write(g_stdin_info.remote_fd, buf, r);
            if(r <= 0) {
                break;
            }
        }
    }
    return 0;
}

int get_screensize(int* lines, int* columns)
{
    HANDLE hConOut;
    CONSOLE_SCREEN_BUFFER_INFO scr;

    hConOut = GetStdHandle (STD_OUTPUT_HANDLE);
    if (hConOut != INVALID_HANDLE_VALUE)
    {
        if (GetConsoleScreenBufferInfo (hConOut, &scr))
        {
            *columns = scr.dwSize.X;
            *lines = scr.srWindow.Bottom - scr.srWindow.Top + 1;
            return 0;
        }
    }

    D("failed to get windows size\n");
    return -1;
}

#else // for UNIX
struct termios g_tio_save;
static void sig_winch_handler(int sig);

void sdb_shell_stdin_init(int fd)
{
    struct termios tio;

    if(tcgetattr(fd, &tio)) return;
    memcpy(&g_tio_save, &tio, sizeof(struct termios));

    /* disable CANON, ECHO*, etc */
    tio.c_lflag = 0;
    /* no timeout but request at least one character per read */
    tio.c_cc[VTIME] = 0;
    tio.c_cc[VMIN] = 1;

    tcsetattr(fd, TCSANOW, &tio);
    tcflush(fd, TCIFLUSH);

    /* register SIGWINCH signal handler. */
    struct sigaction sa_winch;
    sigemptyset(&sa_winch.sa_mask);
    sa_winch.sa_flags = 0;
    sa_winch.sa_handler = sig_winch_handler;
    if (sigaction(SIGWINCH, &sa_winch, NULL) < -1) {
        D("failed to register the SIGWINCH signal handler.\n");
    }
}

void sdb_shell_stdin_restore(int fd)
{
    tcsetattr(fd, TCSANOW, &g_tio_save);
    tcflush(fd, TCIFLUSH);
}

void *stdin_read_thread(void *args)
{
    unsigned char buf[1024];
    int r, n;

    for(;;) {
        /* fdi is really the client's stdin, so use read, not sdb_read here */
        D("stdin_read_thread(): pre unix_read(fdi=%d,...)\n", INPUT_FD);
        r = unix_read(g_stdin_info.stdin_fd, buf, 1024);
        D("stdin_read_thread(): post unix_read(fdi=%d,...)\n", INPUT_FD);
        if(r == 0) break;
        if(r < 0) {
            if(errno == EINTR) continue;
            break;
        }
        for(n = 0; n < r; n++){
            if(buf[n] == '\n' || buf[n] == '\r') {
                n++;
                if(buf[n] == '~') {
                    n++;
                    if(buf[n] == '.') {
                        fprintf(stderr,"\n* disconnect *\n");
                        sdb_shell_stdin_restore(g_stdin_info.stdin_fd);
                        exit(0);
                    }
                }
            }
        }
        r = sdb_write(g_stdin_info.remote_fd, buf, r);
        if(r <= 0) {
            break;
        }
    }
    return 0;
}

int get_screensize(int* lines, int* columns)
{
    struct winsize win_sz;

    if (ioctl(INPUT_FD, TIOCGWINSZ, &win_sz) < 0) {
        D("failed to get windows size\n");
        return -1;
    }

    *lines = win_sz.ws_row;
    *columns = win_sz.ws_col;

    return 0;
}

static void sig_winch_handler(int sig) {
    if (sig != SIGWINCH) {
        return;
    }

    if (g_stdin_info.enable_sync_winsz == SYNCWINSZ_SUPPORTED) {
        sync_winsz();
    }
}
#endif

static void sync_winsz() {
    int lines, columns;
    int fd = -1;
    int remote_id = -1;
    char full_cmd[64] = {0,};
    char *ret_str;
    struct sockaddr_in addr;
    int sockaddr_len = sizeof(addr);

    if (get_screensize(&lines, &columns) == 0) {
        memset(&addr, 0, sizeof(addr));
        if (sdb_getsockname(g_stdin_info.remote_fd, (struct sockaddr *)&addr, &sockaddr_len) < 0) {
            D("failed to get sock name. errno=%d, %s\n", errno, strerror(errno));
            return;
        }

        snprintf(full_cmd, sizeof(full_cmd), "host:get-remote-id:%d:%d",
                            addr.sin_port, addr.sin_addr.s_addr);
        ret_str = sdb_query(full_cmd);
        if(ret_str == NULL) {
            D("failed to sdb query.\n");
            return;
        }

        if (sscanf(ret_str, "remote-id:%d", &remote_id) != 1 || remote_id == -1) {
            D("failed to get remote-id\n");
            return;
        }

        memset(full_cmd, 0, sizeof(full_cmd));
        snprintf(full_cmd, sizeof(full_cmd), "shellconf:syncwinsz:%d:%d:%d", remote_id, lines, columns);
        fd = sdb_connect(full_cmd);
        if(fd < 0) {
            g_stdin_info.enable_sync_winsz = SYNCWINSZ_UNSUPPORTED;
            D("failed to syncwinsz.\n");
            return;
        }

        sdb_close(fd);
    }
}

/* Parse the key/value with the platform capability.
 * Return value
 *  1 : if parsing is successful.
 * -1 : if exception happens. */
int parse_capability_key_value(char* cap, char* key, char* value, int len) {
    char *p_str = NULL;
    int offset = 0;
    char *k = NULL;
    char *v = NULL;
    int ret = -1;

    if (cap == NULL || key == NULL || value == NULL) {
        return -1;
    }

    while ((p_str = strchr(cap+offset, ':')) != NULL) {
        p_str[0] = 0;
        k = cap+offset;
        offset += strlen(cap+offset)+1;

        p_str = strchr(cap+offset, '\n');
        if (p_str != NULL) {
            p_str[0] = 0;
            v = cap+offset;
            offset += strlen(cap+offset)+1;
        }

        if (k == NULL || v == NULL) {
            k = NULL;
            v = NULL;
            continue;
        }

        if (!strcmp(k, key)) {
            strncpy(value, v, len);
            ret = 1;
            break;
        }

        k = NULL;
        v = NULL;
    }

    return ret;
}

/* Check whether the key/value matches with the platform capability.
 * Return value
 *  1 : if key/value matches with capability.
 * -1 : if there is no match. */
int match_capability_key_value(char* cap, char* key, char* value) {
    char *p_str = NULL;
    int offset = 0;
    char *k = NULL;
    char *v = NULL;
    int matched = -1;

    if (cap == NULL || key == NULL || value == NULL) {
        return -1;
    }

    while ((p_str = strchr(cap+offset, ':')) != NULL) {
        p_str[0] = 0;
        k = cap+offset;
        offset += strlen(cap+offset)+1;

        p_str = strchr(cap+offset, '\n');
        if (p_str != NULL) {
            p_str[0] = 0;
            v = cap+offset;
            offset += strlen(cap+offset)+1;
        }

        if (k == NULL || v == NULL) {
            k = NULL;
            v = NULL;
            continue;
        }

        if (!strcmp(k, key) && !strcmp(v, value)) {
            matched = 1;
            break;
        }

        k = NULL;
        v = NULL;
    }

    return matched;
}

int check_syncwinsz_support() {
    char full_cmd[16] = {0,};
    char cap_buffer[CAPBUF_SIZE] = {0,};
    uint16_t len = 0;
    int supported = SYNCWINSZ_UNSUPPORTED;
    int fd = -1;
    char* failmsg = NULL;

    snprintf(full_cmd, sizeof(full_cmd), "capability:");
    fd = sdb_connect_getfailmsg(full_cmd, &failmsg);
    if (fd >= 0) {
        readx(fd, &len, sizeof(uint16_t));
        if (len > CAPBUF_SIZE-1) {
            len = CAPBUF_SIZE-1;
        }
        readx(fd, cap_buffer, len);
        sdb_close(fd);

        int ret = 0;
        ret = match_capability_key_value(cap_buffer, "syncwinsz_support", "enabled");
        if (ret == 1) {
            supported = SYNCWINSZ_SUPPORTED;
        }
    } else {
        D("This platform does not support the capability service.\n");
        if (failmsg != NULL) {
            D("sdb_connect() fail message : %s\n", failmsg);
            SAFE_FREE(failmsg);
        }
    }

    return supported;
}

static void stdin_info_init(int fd, int enable_sync_winsz)
{
    g_stdin_info.stdin_fd = INPUT_FD;
    g_stdin_info.remote_fd = fd;
    g_stdin_info.enable_sync_winsz = enable_sync_winsz;
}

void sdb_execute_shell(int fd, int stdin_on, int enable_sync_winsz)
{
    stdin_info_init(fd, enable_sync_winsz);

    if (stdin_on == SDB_STDIN_ON) {
        sdb_thread_t thr;

        sdb_shell_stdin_init(INPUT_FD);

        sdb_thread_create(&thr, stdin_read_thread, NULL);
        read_and_dump(fd);

        sdb_shell_stdin_restore(INPUT_FD);
    } else {
        read_and_dump(fd);
    }
}

int is_support_eshell(struct sdb_version *pversion)
{
    int supported = 0;

    if (pversion == NULL) {
        return 0;
    }

    /* eshell to support from the 2.4.0 version. */
    if (pversion->major >= 3 || (pversion->major >= 2 && pversion->minor >=4)) {
        /* It must be checked whether it can be obtained window size from the terminal. */
        int lines, columns;
        if(get_screensize(&lines, &columns) == 0) {
            supported = 1;
        }
    }

    return supported;
}

int send_shellcommand(char* buf)
{
    int fd, ret;

    for(;;) {
        fd = sdb_connect(buf);
        if(fd >= 0)
            break;
        fprintf(stderr,"- waiting for device -\n");
        sdb_sleep_ms(1000);
        do_cmd(target_ttype, target_serial, "wait-for-device", 0);
    }

    read_and_dump(fd);
    ret = sdb_close(fd);
    if (ret)
        perror("close");

    return ret;
}

static int do_cmd(transport_type ttype, char* serial, char *cmd, ...)
{
    char *argv[16];
    int argc;
    va_list ap;

    va_start(ap, cmd);
    argc = 0;

    if (serial) {
        argv[argc++] = "-s";
        argv[argc++] = serial;
    } else if (ttype == kTransportUsb) {
        argv[argc++] = "-d";
    } else if (ttype == kTransportLocal) {
        argv[argc++] = "-e";
    }

    argv[argc++] = cmd;
    while((argv[argc] = va_arg(ap, char*)) != 0) {
        argc++;
    }
    va_end(ap);

#if 0
    int n;
    fprintf(stderr,"argc = %d\n",argc);
    for(n = 0; n < argc; n++) {
        fprintf(stderr,"argv[%d] = \"%s\"\n", n, argv[n]);
    }
#endif

    return process_cmdline(argc, argv);
}

int __sdb_command(const char* cmd) {
    int result = sdb_connect(cmd);

    if(result < 0) {
        return result;
    }

    D("about to read_and_dump(fd=%d)\n", result);
    read_and_dump(result);
    D("read_and_dump() done.\n");
    sdb_close(result);

    return 0;
}

// not used currently
#if 0
const char* get_basename(const char* filename)
{
    const char* basename = sdb_dirstop(filename);
    if (basename) {
        basename++;
        return basename;
    } else {
        return filename;
    }
}
#endif

static void create_opt_list(LIST_NODE** opt_list) {

    OPTION* serial = NULL;
    create_option(&serial, COMMANDLINE_SERIAL_LONG_OPT, COMMANDLINE_SERIAL_SHORT_OPT, COMMANDLINE_SERIAL_DESC,
            COMMANDLINE_SERIAL_DESC_SIZE, COMMANDLINE_SERIAL_ARG_DESC, COMMANDLINE_SERIAL_HAS_ARG);
    prepend(opt_list, serial);

    OPTION* emulator = NULL;
    create_option(&emulator, COMMANDLINE_EMULATOR_LONG_OPT, COMMANDLINE_EMULATOR_SHORT_OPT, COMMANDLINE_EMULATOR_DESC,
            COMMANDLINE_EMULATOR_DESC_SIZE, EMPTY_STRING, COMMANDLINE_EMULATOR_HAS_ARG);
    prepend(opt_list, emulator);

    OPTION* device = NULL;
    create_option(&device, COMMANDLINE_DEVICE_LONG_OPT, COMMANDLINE_DEVICE_SHORT_OPT, COMMANDLINE_DEVICE_DESC,
            COMMANDLINE_DEVICES_DESC_SIZE, EMPTY_STRING, COMMANDLINE_DEVICE_HAS_ARG);
    prepend(opt_list, device);
}

static void create_cmd_list(LIST_NODE** cmd_list) {

    //TODO REMOTE_DEVICE_CONNECT security issue should be resolved first
#if 0
    COMMAND* device_con_cmd = NULL;
    create_command(&device_con_cmd, COMMANDLINE_DEVICE_CON_NAME, COMMANDLINE_DEVICE_CON_DESC,
            COMMANDLINE_DEVICE_CON_DESC_SIZE, COMMANDLINE_DEVICE_CON_ARG_DESC, device_con, COMMANDLINE_DEVICE_CON_MAX_ARG, COMMANDLINE_DEVICE_CON_MIN_ARG);
    prepend(cmd_list, device_con_cmd);
#endif

    //hidden command for testing suspended mode
#ifdef MAKE_DEBUG
    COMMAND* send_packet_cmd = NULL;
    create_command(&send_packet_cmd, "send-packet", NULL,
            0, NULL, get_state_serialno, 0, 0);
    prepend(cmd_list, send_packet_cmd);

    COMMAND* transport_close_cmd = NULL;
    create_command(&transport_close_cmd, "transport-close", NULL,
            0, NULL, get_state_serialno, 0, 0);
    prepend(cmd_list, transport_close_cmd);
#endif

    COMMAND* help_cmd = NULL;
    create_command(&help_cmd, COMMANDLINE_HELP_NAME, COMMANDLINE_HELP_DESC,
            COMMANDLINE_HELP_DESC_SIZE, EMPTY_STRING, NULL, 0, 0);
    prepend(cmd_list, help_cmd);

    COMMAND* version_cmd = NULL;
    create_command(&version_cmd, COMMANDLINE_VERSION_NAME,
            COMMANDLINE_VERSION_DESC, COMMANDLINE_VERSION_DESC_SIZE,
            EMPTY_STRING, version, COMMANDLINE_VERSION_MAX_ARG,
            COMMANDLINE_VERSION_MIN_ARG);
    prepend(cmd_list, version_cmd);

    COMMAND* root_cmd = NULL;
    create_command(&root_cmd, COMMANDLINE_ROOT_NAME, COMMANDLINE_ROOT_DESC,
            COMMANDLINE_ROOT_DESC_SIZE, COMMANDLINE_ROOT_ARG_DESC, root,
            COMMANDLINE_ROOT_MAX_ARG, COMMANDLINE_ROOT_MIN_ARG);
    prepend(cmd_list, root_cmd);

    COMMAND* swindow_cmd = NULL;
    create_command(&swindow_cmd, COMMANDLINE_SWINDOW_NAME,
            COMMANDLINE_SWINDOW_DESC, COMMANDLINE_SWINDOW_DESC_SIZE,
            EMPTY_STRING, status_window, COMMANDLINE_SWINDOW_MAX_ARG,
            COMMANDLINE_SWINDOW_MIN_ARG);
    prepend(cmd_list, swindow_cmd);

    COMMAND* gserial_cmd = NULL;
    create_command(&gserial_cmd, COMMANDLINE_GSERIAL_NAME,
            COMMANDLINE_GSERIAL_DESC, COMMANDLINE_GSERIAL_DESC_SIZE,
            EMPTY_STRING, get_state_serialno, COMMANDLINE_GSERIAL_MAX_ARG,
            COMMANDLINE_GSERIAL_MIN_ARG);
    prepend(cmd_list, gserial_cmd);

    COMMAND* gstate_cmd = NULL;
    create_command(&gstate_cmd, COMMANDLINE_GSTATE_NAME,
            COMMANDLINE_GSTATE_DESC, COMMANDLINE_GSTATE_DESC_SIZE, EMPTY_STRING,
            get_state_serialno, COMMANDLINE_GSTATE_MAX_ARG,
            COMMANDLINE_GSTATE_MIN_ARG);
    prepend(cmd_list, gstate_cmd);

    COMMAND* kserver_cmd = NULL;
    create_command(&kserver_cmd, COMMANDLINE_KSERVER_NAME,
            COMMANDLINE_KSERVER_DESC, COMMANDLINE_KSERVER_DESC_SIZE,
            EMPTY_STRING, kill_server, COMMANDLINE_KSERVER_MAX_ARG,
            COMMANDLINE_KSERVER_MIN_ARG);
    prepend(cmd_list, kserver_cmd);

    COMMAND* sserver_cmd = NULL;
    create_command(&sserver_cmd, COMMANDLINE_SSERVER_NAME,
            COMMANDLINE_SSERVER_DESC, COMMANDLINE_SSERVER_DESC_SIZE,
            COMMANDLINE_SSERVER_ARG_DESC, start_server,
            COMMANDLINE_SSERVER_MAX_ARG, COMMANDLINE_SSERVER_MIN_ARG);
    prepend(cmd_list, sserver_cmd);

#ifdef SUPPORT_ENCRYPT
    // encryption command
    COMMAND* encryption_cmd = NULL;
    create_command(&encryption_cmd, COMMANDLINE_ENCRYPTION_NAME, COMMANDLINE_ENCRYPTION_DESC, COMMANDLINE_ENCRYPTION_DESC_SIZE, COMMANDLINE_ENCRYPTION_ARG_DESC,
            encryption, COMMANDLINE_ENCRYPTION_MAX_ARG, COMMANDLINE_ENCRYPTION_MIN_ARG);
    prepend(cmd_list, encryption_cmd);
#endif

    COMMAND* dlog_cmd = NULL;
    create_command(&dlog_cmd, COMMANDLINE_DLOG_NAME, COMMANDLINE_DLOG_DESC,
            COMMANDLINE_DLOG_DESC_SIZE, COMMANDLINE_DLOG_ARG_DESC, dlog,
            COMMANDLINE_DLOG_MAX_ARG, COMMANDLINE_DLOG_MIN_ARG);
    prepend(cmd_list, dlog_cmd);

    COMMAND* forward_remove_all_cmd = NULL;
    create_command(&forward_remove_all_cmd, COMMANDLINE_FORWARD_REMOVE_ALL_NAME,
            COMMANDLINE_FORWARD_REMOVE_ALL_DESC,
            COMMANDLINE_FORWARD_REMOVE_ALL_DESC_SIZE, EMPTY_STRING, forward,
            COMMANDLINE_FORWARD_REMOVE_ALL_MAX_ARG,
            COMMANDLINE_FORWARD_REMOVE_ALL_MIN_ARG);
    prepend(cmd_list, forward_remove_all_cmd);

    COMMAND* forward_remove_cmd = NULL;
    create_command(&forward_remove_cmd, COMMANDLINE_FORWARD_REMOVE_NAME,
            COMMANDLINE_FORWARD_REMOVE_DESC,
            COMMANDLINE_FORWARD_REMOVE_DESC_SIZE,
            COMMANDLINE_FORWARD_REMOVE_ARG_DESC, forward,
            COMMANDLINE_FORWARD_REMOVE_MAX_ARG,
            COMMANDLINE_FORWARD_REMOVE_MIN_ARG);
    prepend(cmd_list, forward_remove_cmd);

    COMMAND* forward_list_cmd = NULL;
    create_command(&forward_list_cmd, COMMANDLINE_FORWARD_LIST_NAME,
            COMMANDLINE_FORWARD_LIST_DESC, COMMANDLINE_FORWARD_LIST_DESC_SIZE,
            EMPTY_STRING, forward, COMMANDLINE_FORWARD_LIST_MAX_ARG,
            COMMANDLINE_FORWARD_LIST_MIN_ARG);
    prepend(cmd_list, forward_list_cmd);

    COMMAND* forward_cmd = NULL;
    create_command(&forward_cmd, COMMANDLINE_FORWARD_NAME,
            COMMANDLINE_FORWARD_DESC, COMMANDLINE_FORWARD_DESC_SIZE,
            COMMANDLINE_FORWARD_ARG_DESC, forward, COMMANDLINE_FORWARD_MAX_ARG,
            COMMANDLINE_FORWARD_MIN_ARG);
    prepend(cmd_list, forward_cmd);

    COMMAND* uninstall_cmd = NULL;
    create_command(&uninstall_cmd, COMMANDLINE_UNINSTALL_NAME,
            COMMANDLINE_UNINSTALL_DESC, COMMANDLINE_UNINSTALL_DESC_SIZE,
            COMMANDLINE_UNINSTALL_ARG_DESC, uninstall,
            COMMANDLINE_UNINSTALL_MAX_ARG, COMMANDLINE_UNINSTALL_MIN_ARG);
    prepend(cmd_list, uninstall_cmd);

    COMMAND* install_cmd = NULL;
    create_command(&install_cmd, COMMANDLINE_INSTALL_NAME,
            COMMANDLINE_INSTALL_DESC, COMMANDLINE_INSTALL_DESC_SIZE,
            COMMANDLINE_INSTALL_ARG_DESC, install, COMMANDLINE_INSTALL_MAX_ARG,
            COMMANDLINE_INSTALL_MIN_ARG);
    prepend(cmd_list, install_cmd);

    COMMAND* shell_cmd = NULL;
    create_command(&shell_cmd, COMMANDLINE_SHELL_NAME, COMMANDLINE_SHELL_DESC,
            COMMANDLINE_SHELL_DESC_SIZE, COMMANDLINE_SHELL_ARG_DESC, shell,
            COMMANDLINE_SHELL_MAX_ARG, COMMANDLINE_SHELL_MIN_ARG);
    prepend(cmd_list, shell_cmd);

    COMMAND* pull_cmd = NULL;
    create_command(&pull_cmd, COMMANDLINE_PULL_NAME, COMMANDLINE_PULL_DESC,
            COMMANDLINE_PULL_DESC_SIZE, COMMANDLINE_PULL_ARG_DESC, pull,
            COMMANDLINE_PULL_MAX_ARG, COMMANDLINE_PULL_MIN_ARG);
    prepend(cmd_list, pull_cmd);

    COMMAND* push_cmd = NULL;
    create_command(&push_cmd, COMMANDLINE_PUSH_NAME, COMMANDLINE_PUSH_DESC,
            COMMANDLINE_PUSH_DESC_SIZE, COMMANDLINE_PUSH_ARG_DESC, push,
            COMMANDLINE_PUSH_MAX_ARG, COMMANDLINE_PUSH_MIN_ARG);
    prepend(cmd_list, push_cmd);

    COMMAND* disconnect_cmd = NULL;
    create_command(&disconnect_cmd, COMMANDLINE_DISCONNECT_NAME,
            COMMANDLINE_DISCONNECT_DESC, COMMANDLINE_DISCONNECT_DESC_SIZE,
            COMMANDLINE_DISCONNECT_ARG_DESC, __disconnect,
            COMMANDLINE_DISCONNECT_MAX_ARG, COMMANDLINE_DISCONNECT_MIN_ARG);
    prepend(cmd_list, disconnect_cmd);

    COMMAND* connect_cmd = NULL;
    create_command(&connect_cmd, COMMANDLINE_CONNECT_NAME,
            COMMANDLINE_CONNECT_DESC, COMMANDLINE_CONNECT_DESC_SIZE,
            COMMANDLINE_CONNECT_ARG_DESC, __connect,
            COMMANDLINE_CONNECT_MAX_ARG, COMMANDLINE_CONNECT_MIN_ARG);
    prepend(cmd_list, connect_cmd);

    COMMAND* devices_cmd = NULL;
    create_command(&devices_cmd, COMMANDLINE_DEVICES_NAME,
            COMMANDLINE_DEVICES_DESC, COMMANDLINE_DEVICES_DESC_SIZE,
            EMPTY_STRING, devices, COMMANDLINE_DEVICES_MAX_ARG,
            COMMANDLINE_DEVICES_MIN_ARG);
    prepend(cmd_list, devices_cmd);

    COMMAND* launch_cmd = NULL;
    create_command(&launch_cmd, COMMANDLINE_LAUNCH_NAME, NULL, 0, EMPTY_STRING,
            launch, COMMANDLINE_LAUNCH_MAX_ARG, COMMANDLINE_LAUNCH_MIN_ARG);
    prepend(cmd_list, launch_cmd);

    COMMAND* forkserver_cmd = NULL;
    create_command(&forkserver_cmd, COMMANDLINE_FORKSERVER_NAME, NULL, 0,
            EMPTY_STRING, forkserver, COMMANDLINE_FORKSERVER_MAX_ARG,
            COMMANDLINE_FORKSERVER_MIN_ARG);
    prepend(cmd_list, forkserver_cmd);

    // deprecated
    COMMAND* oprofile_cmd = NULL;
    create_command(&oprofile_cmd, COMMANDLINE_OPROFILE_NAME, NULL, 0,
            EMPTY_STRING, oprofile, COMMANDLINE_OPROFILE_MAX_ARG,
            COMMANDLINE_OPROFILE_MIN_ARG);
    prepend(cmd_list, oprofile_cmd);

    // deprecated
    COMMAND* da_cmd = NULL;
    create_command(&da_cmd, COMMANDLINE_DA_NAME, NULL, 0, EMPTY_STRING, da,
            COMMANDLINE_DA_MAX_ARG, COMMANDLINE_DA_MIN_ARG);
    prepend(cmd_list, da_cmd);

    COMMAND* profile_cmd = NULL;
    create_command(&profile_cmd, COMMANDLINE_PROFILE_NAME, NULL, 0,
            EMPTY_STRING, profile, COMMANDLINE_PROFILE_MAX_ARG,
            COMMANDLINE_PROFILE_MIN_ARG);
    prepend(cmd_list, profile_cmd);

    COMMAND* capability_cmd = NULL;
    create_command(&capability_cmd, COMMANDLINE_CAPABILITY_NAME, NULL, 0,
            EMPTY_STRING, get_capability, COMMANDLINE_CAPABILITY_MAX_ARG,
            COMMANDLINE_CAPABILITY_MIN_ARG);
    prepend(cmd_list, capability_cmd);

    COMMAND* boot_cmd = NULL;
    create_command(&boot_cmd, COMMANDLINE_BOOT_NAME, NULL, 0, EMPTY_STRING,
            get_boot, COMMANDLINE_BOOT_MAX_ARG, COMMANDLINE_BOOT_MIN_ARG);
    prepend(cmd_list, boot_cmd);
    

}

int process_cmdline(int argc, char** argv) {

    transport_type ttype = kTransportAny;
    char* serial = NULL;

    // TODO: also try TARGET_PRODUCT/TARGET_DEVICE as a hint

    LIST_NODE* cmd_list = NULL;
    LIST_NODE* opt_list = NULL;
    LIST_NODE* input_opt_list = NULL;

    create_cmd_list(&cmd_list);
    create_opt_list(&opt_list);
    int parsed_argc = parse_opt(argc, argv, opt_list, &input_opt_list);

    if(parsed_argc < 0) {
        return -1;
    }

    D("Parsed %d arguments\n", parsed_argc);

    argc = argc - parsed_argc;
    argv = argv + parsed_argc;

    INPUT_OPTION* opt_s = get_inputopt(input_opt_list, (char*)COMMANDLINE_SERIAL_SHORT_OPT);
    if(opt_s != NULL) {
        serial = opt_s->value;

        char buf[PATH_MAX];
        char *tmp;
        snprintf(buf, sizeof(buf), "host:serial-match:%s", serial);


        tmp = sdb_query(buf);
        if (tmp) {
            serial = strdup(tmp);
        } else {
            print_error(SDB_MESSAGE_ERROR, F(ERR_CONNECT_WRONG_SERIAL, serial), NULL);
            return 1;
        }
    }
    else {
        INPUT_OPTION* opt_d = get_inputopt(input_opt_list, (char*)COMMANDLINE_DEVICE_SHORT_OPT);
        if(opt_d != NULL) {
            ttype = kTransportUsb;
        }
        else {
            INPUT_OPTION* opt_e = get_inputopt(input_opt_list, (char*)COMMANDLINE_EMULATOR_SHORT_OPT);
            if(opt_e != NULL) {
                ttype = kTransportLocal;
            }
        }
    }

    if(argc > 0) {
        if(!strcmp(argv[0], COMMANDLINE_HELP_NAME)) {
            print_help(opt_list, cmd_list);
            return 1;
        }
        COMMAND* command = get_command(cmd_list, argv[0]);

        D("process command: %s\n", command->name);
        int minargs = command->minargs;
        int maxargs = command->maxargs;

        if(argc < minargs + 1) {
            print_error(SDB_MESSAGE_ERROR, ERR_COMMAND_TOO_FEW_ARGUMENTS , NULL);
            print_info("sdb %s %s", argv[0], command->argdesc);
            SAFE_FREE(serial);
            return 1;
        }
        if(argc > maxargs + 1 && maxargs > -1) {
            print_error(SDB_MESSAGE_ERROR, ERR_COMMAND_TOO_MANY_ARGUMENTS , NULL);
            print_info("sdb %s %s", argv[0], command->argdesc);
            SAFE_FREE(serial);
            return 1;
        }
        target_serial = serial;
        target_ttype = ttype;
        int (*Func)(int, char**) = command->Func;
        free_list(cmd_list, NULL);
        free_list(input_opt_list, NULL);
        free_list(opt_list, NULL);
        return Func(argc, argv);
    }

    print_help(opt_list, cmd_list);
    SAFE_FREE(serial);
    return 1;
}

static void print_help(LIST_NODE* optlist, LIST_NODE* cmdlist) {
    char** line;
    int* len;
    int lines;

    fprintf(stderr, "\nSmart Development Bridge %d.%d.%d\n",
         SDB_VERSION_MAJOR, SDB_VERSION_MINOR, SDB_VERSION_PATCH);
    fprintf(stderr, "\nSyntax:\n  sdb [target] <command> [parameters]\n\n");
    fprintf(stderr, "Targets:\n");

    LIST_NODE* curptr = optlist;
    int append_len = strlen(HELP_APPEND_STR);
    char* append_str = (char*)malloc(sizeof(char)*append_len);
    char* help_str = (char*)malloc(sizeof(char)*append_len*3);
    while(curptr != NULL) {
        OPTION* opt = (OPTION*)curptr->data;
        curptr = curptr->next_ptr;
        const char** des = opt->desc;
        if(des != NULL) {
            snprintf(help_str, append_len*3, "  -%s, --%s %s", opt->shortopt, opt->longopt, opt->argdesc);
            int opt_len = strlen(help_str);
            if(opt_len >= append_len) {
                fprintf(stderr, "%s\n%s", help_str, HELP_APPEND_STR);
            }
            else {
                snprintf(append_str, append_len - opt_len + 1, "%s", HELP_APPEND_STR);
                fprintf(stderr, "%s%s", help_str, append_str);
            }

            lines = strwrap(des[0], HELP_DESCRIPTION_STRING_WIDTH, &line, &len);

            int i;
            char result[100];
            for (i = 0; i < lines; i++) {
                snprintf(result, len[i] + 1, "%s", line[i]);
                if (i == 0)
                    fprintf(stderr, "%s\n", result);
                else
                    fprintf(stderr, "%s%s\n", HELP_APPEND_STR, result);
            }
            SAFE_FREE(line);
            SAFE_FREE(len);
        }
    }
    fprintf(stderr, "\nCommand & Parameters:\n");

    curptr = cmdlist;
    while(curptr != NULL) {
        COMMAND* cmd = (COMMAND*)curptr ->data;
        curptr = curptr->next_ptr;
        const char** des = cmd->desc;
        if(des != NULL) {
            snprintf(help_str, append_len*3, "  %s %s", cmd->name, cmd->argdesc);
            int cmd_len = strlen(help_str);
            if(cmd_len >= append_len) {
                fprintf(stderr, "%s\n%s", help_str, HELP_APPEND_STR);
            }
            else {
                snprintf(append_str, append_len - cmd_len + 1, "%s", HELP_APPEND_STR);
                fprintf(stderr, "%s%s", help_str, append_str);
            }

            lines = strwrap(des[0], HELP_DESCRIPTION_STRING_WIDTH, &line, &len);

            int i;
            char result[100];
            for (i = 0; i < lines; i++) {
                snprintf(result, len[i] + 1, "%s", line[i]);
                if (i == 0)
                    fprintf(stderr, "%s\n", result);
                else
                    fprintf(stderr, "%s%s\n", HELP_APPEND_STR, result);
            }
            SAFE_FREE(line);
            SAFE_FREE(len);
        }
    }

    SAFE_FREE(append_str);
    SAFE_FREE(help_str);
}


