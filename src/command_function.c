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

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

#include "utils.h"
#include "fdevent.h"

#include "commandline.h"
#include "command_function.h"
#include "sdb_client.h"
#include "sdb_constants.h"
#include "file_sync_service.h"

#include "strutils.h"
#include "file_sync_client.h"
#include "file_sync_functions.h"
#include "common_modules.h"

#include "log.h"
#include "sdb.h"
#include "sdb_messages.h"
#include "sdb_usb.h"
#include "sockets.h"

static const char *SDK_TOOL_PATH="/home/developer/sdk_tools";
static const char *APP_PATH_PREFIX="/opt/apps";

// the time limit to wait for connection with device
static const int DEVICE_ONLINE_CHECK_INTERVAL = 500; // msec
static const int DEVICE_ONLINE_CHECK_REPEAT = 6;

static void __inline__ format_host_command(char* buffer, size_t  buflen, const char* command, transport_type ttype, const char* serial);
static int get_pkgtype_file_name(const char* file_name);
static int kill_gdbserver_if_running(const char* process_cmd);
static int verify_gdbserver_exist();
static int get_pkg_tmp_dir(char* pkg_tmp_dir, int len);

int da(int argc, char ** argv) {
    char full_cmd[PATH_MAX] = "shell:/usr/bin/da_command";

    append_args(full_cmd, --argc, (const char**)++argv, PATH_MAX-1);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    int result = __sdb_command(full_cmd);

    if(result < 0) {
        return 1;
    }
    return 0;
}

int oprofile(int argc, char ** argv) {
    char full_cmd[PATH_MAX] = "shell:/usr/bin/oprofile_command";

    append_args(full_cmd, --argc, (const char**)++argv, PATH_MAX- 1);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    int result = __sdb_command(full_cmd);

    if(result < 0) {
        return 1;
    }
    return 0;
}

int profile(int argc, char ** argv) {
    char full_cmd[PATH_MAX] = "shell:/usr/bin/profile_command";

    append_args(full_cmd, --argc, (const char**)++argv, PATH_MAX- 1);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    int result = __sdb_command(full_cmd);

    if(result < 0) {
        return 1;
    }
    return 0;
}

int launch(int argc, char ** argv) {
    int i;
    int result = 0;
    char pkgid[11] = {0,};
    char exe[512] = {0,};
    char args[512] = {0,};
    int mode = 0;
    int port = 0;
    int pid = 0;
    int type = 0;
    char fullcommand[PATH_MAX] = {'s','h','e','l','l',':',};
    char buf[128] = {0,};
    char flag = 0;

    if (argc < 7 || argc > 15 ) {
        print_info("sdb launch -p <pkgid> -e <executable> -m <run|debug|da|oprofile> [-P <port>] [-attach <pid>] [-t <gtest,gcov>]  [<args...>]");
        return -1;
    }

    if(SDB_HIGHER_THAN_2_2_3()) {
        int full_len = PATH_MAX - 1;
        strncat(fullcommand, WHITE_SPACE, full_len);
        strncat(fullcommand, SDB_LAUNCH_SCRIPT, full_len);
        for(i = 1; i < argc; i ++) {
            strncat(fullcommand, WHITE_SPACE, full_len);
            strncat(fullcommand, argv[i], full_len);
        }

        return __sdb_command(fullcommand);
    }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p")) {
            flag = 'p';
            continue;
        }
        if (!strcmp(argv[i], "-e")) {
            flag = 'e';
            continue;
        }
        if (!strcmp(argv[i], "-m")) {
            flag = 'm';
            continue;
        }
        if (!strcmp(argv[i], "-P")) {
            flag = 'P';
            continue;
        }
        if (!strcmp(argv[i], "-t")) {
            flag = 't';
            continue;
        }
        if (!strcmp(argv[i], "-attach")) {
            flag = 'a';
            continue;
        }
        D("launch cmd args: %c : %s\n", flag, argv[i]);

        switch (flag) {
        case 'p' :
            s_strncpy(pkgid, argv[i], sizeof(pkgid));
            flag = 0;
            break;
        case 'e':
            s_strncpy(exe, argv[i], sizeof(exe));
            flag = 0;
            break;
        case 'm': {
            if (!strcmp(argv[i], "run")) {
                mode = 0;
            } else if (!strcmp(argv[i], "debug")) {
                mode = 1;
            } else if (!strcmp(argv[i], "da") || !strcmp(argv[i], "oprofile")) {
                print_error(SDB_MESSAGE_ERROR, ERR_LAUNCH_M_OPTION_SUPPORT, NULL);
                return -1;
            }
            else {
                print_error(SDB_MESSAGE_ERROR, ERR_LAUNCH_M_OPTION_ARGUMENT, NULL);
                return -1;
            }
            flag = 0;
            break;
        }
        case 'P': {
            if (mode != 1) {
                print_error(SDB_MESSAGE_ERROR, ERR_LAUNCH_P_OPTION_DEBUG_MODE, NULL);
                return -1;
            }
            port = atoi(argv[i]);
            flag = 0;
            break;
        }
        case 'a': {
            if (mode != 1) {
                print_error(SDB_MESSAGE_ERROR, ERR_LAUNCH_P_OPTION_DEBUG_MODE, NULL);
                return -1;
            }
            pid = atoi(argv[i]);
            flag = 0;
            break;
        }
        case 't': {
            char *str = argv[i];
            for (; *str; str++) {
                if (!memcmp(str, "gtest", 5)) {
                    snprintf(buf, sizeof(buf), "export LD_LIBRARY_PATH=%s/gtest/usr/lib && ", SDK_TOOL_PATH);
                    strncat(fullcommand, buf, sizeof(fullcommand) - 1);
                    type = 1;
                }
                if (!memcmp(str, "gcov", 4)) {
                    snprintf(buf, sizeof(buf), "export GCOV_PREFIX=/tmp/%s/data && export GCOV_PREFIX_STRIP=0 && ", pkgid);
                    strncat(fullcommand, buf, sizeof(fullcommand) - 1);
                    type = 2;
                }
                char *ptr = strstr(str, ",");
                if (ptr) {
                    str = ptr;
                }
            }
            flag = 0;
        }
            break;
        default : {
            while (i < argc) {
                strncat(args, " ", sizeof(args)-1);
                strncat(args, argv[i], sizeof(args)-1);
                i++;
            }
            break;
        }
        }
    }

    if (mode == 0) {
        if (type == 0) {
            snprintf(buf, sizeof(buf), "/usr/bin/launch_app %s.%s", pkgid, exe);
            strncat(fullcommand, buf, sizeof(fullcommand)-1);
        } else {
            snprintf(buf, sizeof(buf), "%s/%s/bin/%s", APP_PATH_PREFIX, pkgid, exe);
            strncat(fullcommand, buf, sizeof(fullcommand)-1);
        }
    } else if (mode == 1) {
        if (verify_gdbserver_exist() < 0) {
            return -1;
        }
        if (port <= 0 || port > MAX_PORT_NUMBER) {
            print_error(SDB_MESSAGE_ERROR, ERR_GENERAL_LAUNCH_APP_FAIL, F(ERR_GENERAL_INVALID_PORT, port));

            return -1;
        }
        if (pid) {
            snprintf(buf, sizeof(buf), "%s/gdbserver/gdbserver :%d --attach %d", SDK_TOOL_PATH, port, pid);
        } else {
            snprintf(buf, sizeof(buf), "%s/gdbserver/gdbserver :%d %s/%s/bin/%s", SDK_TOOL_PATH, port, APP_PATH_PREFIX, pkgid, exe);
        }
        if (kill_gdbserver_if_running(buf) < 0) {
            fprintf(stderr, "Gdbserver is already running on your target.\nAn gdb is going to connect the previous gdbserver process.\n");
            return -1;
        }
        strncat(fullcommand, buf, sizeof(fullcommand)-1);
    }
    if (strlen(args) > 1) {
        strncat(fullcommand, " ", sizeof(fullcommand)-1);
        strncat(fullcommand, args, sizeof(fullcommand)-1);
    }

    D("launch command: [%s]\n", fullcommand);
    result = __sdb_command(fullcommand);
    sdb_close(result);

    return result;
}

int devices(int argc, char ** argv) {

    char *tmp;
    char full_cmd[PATH_MAX];

    snprintf(full_cmd, sizeof full_cmd, "host:%s", argv[0]);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    tmp = sdb_query(full_cmd);
    if(tmp) {
        printf("List of devices attached \n");
        printf("%s", tmp);
        return 0;
    } else {
        return 1;
    }
}

int __disconnect(int argc, char ** argv) {
    char full_cmd[PATH_MAX];
    char* tmp;

    if (argc == 2) {
        snprintf(full_cmd, sizeof full_cmd, "host:disconnect:%s", argv[1]);
    } else {
        snprintf(full_cmd, sizeof full_cmd, "host:disconnect:");
    }
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    tmp = sdb_query(full_cmd);
    if(tmp) {
        printf("%s\n", tmp);
        return 0;
    } else {
        return 1;
    }
}

int __connect(int argc, char ** argv) {
    char full_cmd[PATH_MAX];
    char * tmp;
    char remote_target_info[30] = { 0, };
    int i;

    if (strstr(argv[1], ":") == NULL)
        snprintf(remote_target_info, sizeof remote_target_info, "%s:%d", argv[1], DEFAULT_SDB_LOCAL_TRANSPORT_PORT);
    else
        snprintf(remote_target_info, sizeof remote_target_info, "%s", argv[1]);

    snprintf(full_cmd, sizeof full_cmd, "host:connect:%s", remote_target_info);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    tmp = sdb_query(full_cmd);
    if(tmp) {
        // check if port is opened
        printf("%s\n", tmp);
        if(strstr(tmp, "connecting") == NULL)
            return 0;

        // check if device state is online for 3 secs
        for (i = 0; i < DEVICE_ONLINE_CHECK_REPEAT; i++) {
            sdb_sleep_ms(DEVICE_ONLINE_CHECK_INTERVAL);

            snprintf(full_cmd, sizeof full_cmd, "host-serial:%s:get-state", remote_target_info);
            tmp = sdb_query(full_cmd);

            if (tmp != NULL) {
                if(!strcmp(tmp, STATE_DEVICE) || !strcmp(tmp, STATE_LOCKED) || !strcmp(tmp, STATE_SUSPENDED)) {
                    printf("connected to %s\n", remote_target_info);
                    return 0;
                } else if (!strcmp(tmp, STATE_UNAUTHORIZED)) {
                    printf("device unauthorized. Please approve on your device.\n");
                    return 1;
                }
            } else {
                // connection error occurred
                break;
            }
        }
    }
    printf("failed to connect to %s\n", remote_target_info);
    return 1;
}

// currently not supported
#if 0
int device_con(int argc, char ** argv) {

    char *tmp;
    char full_cmd[PATH_MAX];

    snprintf(full_cmd, sizeof full_cmd, "host:device_con:%s:%s", argv[1], argv[2]);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    tmp = sdb_query(full_cmd);

    if(tmp != NULL) {
        printf("%s", tmp);
        return 0;
    }

    return 1;
}
#endif

int get_state_serialno(int argc, char ** argv) {

    char full_cmd[PATH_MAX];
    format_host_command(full_cmd, sizeof full_cmd, argv[0], target_ttype, target_serial);
    LOG_INFO(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    char* tmp = sdb_query(full_cmd);
    if(tmp) {
        printf("%s\n", tmp);
        return 0;
    } else {
        return 1;
    }
}

int root(int argc, char ** argv) {
    char full_cmd[20];
    snprintf(full_cmd, sizeof(full_cmd), "root:%s", argv[1]);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    int fd = sdb_connect(full_cmd);

    if(fd >= 0) {
        read_and_dump(fd);
        sdb_close(fd);
        return 0;
    }
    return 1;
}

//LCOV_EXCL_START
int status_window(int argc, char ** argv) {

    char full_cmd[PATH_MAX];
    char *state = 0;
    char *laststate = 0;

        /* silence stderr (It means 2>/dev/null) */
#ifdef _WIN32
    /* XXX: TODO */
#else
    int  fd;
    fd = unix_open("/dev/null", O_WRONLY);

    if(fd >= 0) {
        dup2(fd, 2);
        sdb_close(fd);
    }
#endif

    format_host_command(full_cmd, sizeof full_cmd, "get-state", target_ttype, target_serial);

    for(;;) {
        sdb_sleep_ms(250);

        SAFE_FREE(state);

        D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
        state = sdb_query(full_cmd);

        if(state) {
            if(laststate && !strcmp(state,laststate)){
                continue;
            } else {
                if(laststate) free(laststate);
                laststate = strdup(state);
            }
        }

#ifdef OS_WINDOWS
		system("cls");
		printf("\n");
#else
        printf("%c[2J%c[2H", 27, 27);
#endif

        printf("Smart Development Bridge\n");
        printf("State: %s\n", state ? state : "offline");
        fflush(stdout);
    }

    return 0;
}
//LCOV_EXCL_STOP

int kill_server(int argc, char ** argv) {
    int fd;
    fd = _sdb_connect("host:kill");
    if(fd == -2) {
        print_info(ERR_GENERAL_SERVER_NOT_RUN);
    }
    return 0;
}

int start_server(int argc, char ** argv) {
    if (argv[1] != NULL && !strcmp(argv[1], "--only-detect-tizen")) {
        return sdb_connect("host:start-server:only-detect-tizen");
    } else {
        return sdb_connect("host:start-server");
    }
}

int version(int argc, char ** argv) {

    if (target_ttype == kTransportUsb || target_ttype == kTransportLocal) {
        char* VERSION_QUERY ="shell:rpm -qa | grep sdbd";
        send_shellcommand(VERSION_QUERY);
    } else {
        fprintf(stdout, "Smart Development Bridge version %d.%d.%d\n",
             SDB_VERSION_MAJOR, SDB_VERSION_MINOR, SDB_VERSION_PATCH);
    }
    return 0;
}

int forward(int argc, char ** argv) {

    if(argv[1] == NULL){
        return -1;
    }

    if(!strcmp(argv[1],"--list")) {
        forward_list();
    } else if (!strcmp(argv[1],"--remove")) {
        forward_remove(argv[2]);
    } else if (!strcmp(argv[1],"--remove-all")) {
        forward_remove_all();
    } else {
        char full_cmd[PATH_MAX];
        char prefix[NAME_MAX];

        get_host_prefix(prefix, NAME_MAX, target_ttype, target_serial, host);
        snprintf(full_cmd, sizeof full_cmd, "%sforward:%s;%s",prefix, argv[1], argv[2]);

        D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
        if(sdb_command(full_cmd) < 0) {
            return 1;
        }
    }

    return 0;
}

int forward_list() {
    char *tmp = NULL;
    char full_cmd[PATH_MAX];

    snprintf(full_cmd, sizeof full_cmd, "host:forward-list");
    D(COMMANDLINE_MSG_FULL_CMD, "forward-list", full_cmd);
    tmp = sdb_query(full_cmd);
    if(tmp) {
        printf("List of port forwarding\n");
        printf("%-20s\t%-10s\t%s\n", "SERIAL", "LOCAL", "REMOTE");
        printf("%s", tmp);
        return 0;
    } else {
        return 1;
    }
}

int forward_remove(char *local) {
    char full_cmd[PATH_MAX];

    snprintf(full_cmd, sizeof full_cmd, "host:forward-remove:%s", local);
    D(COMMANDLINE_MSG_FULL_CMD, "forward --remove", full_cmd);
    int result = sdb_connect(full_cmd);
    if(result < 0) {
        return -1;
    }
    return 0;
}

int forward_remove_all() {
    char* full_cmd = "host:forward-remove-all";

    D(COMMANDLINE_MSG_FULL_CMD, "forward --remove-all", full_cmd);
    int result = sdb_connect(full_cmd);
    if(result < 0) {
        return -1;
    }
    return 0;
}

int dlog(int argc, char ** argv) {
    D("dlog with serial: %s\n", target_serial);

    char full_cmd[PATH_MAX] = "shell:/usr/bin/dlogutil";

    int i;
    for(i = 1; i<argc; i++) {
        char quoted_string[MAX_INPUT];
        dup_quote(quoted_string, argv[i], MAX_INPUT);

        strncat(full_cmd, " ", sizeof(full_cmd)-1);
        strncat(full_cmd, quoted_string, sizeof(full_cmd)-1);
    }

    send_shellcommand(full_cmd);
    return 0;
}

int push(int argc, char ** argv) {
    int i=0;
    int utf8 = 0;

    if(argc > 3 && !strcmp(argv[argc-1], "--with-utf8")) {
        D("push with utf8");
        utf8 = 1;
        --argc;
    }

    SYNC_INFO info = {
            .srcF = (FILE_FUNC*)&LOCAL_FILE_FUNC,
            .dstF = (FILE_FUNC*)&REMOTE_FILE_FUNC,
            .tag = {'p', 'u', 's', 'h', 'e', 'd', '\0'},
    };

    fprintf(stdout,"%s\n", MSG_SYNC_SECURE_WARNING);
    for (i=1; i<argc-1; i++) {
        info.copied = 0;
        info.skipped = 0;
        info.total_bytes = 0;
        do_sync_copy(argv[i], argv[argc-1], &info, utf8);
    }
    return 0;
}

int pull(int argc, char ** argv) {

    SYNC_INFO info = {
            .srcF = (FILE_FUNC*)&REMOTE_FILE_FUNC,
            .dstF = (FILE_FUNC*)&LOCAL_FILE_FUNC,
            .copied = 0,
            .skipped = 0,
            .total_bytes = 0,
            .tag = {'p', 'u', 'l', 'l', 'e', 'd', '\0'},
    };
    if (argc == 2) {
        return do_sync_copy(argv[1], ".", &info, 0);
    }
    return do_sync_copy(argv[1], argv[2], &info, 0);
}

static int shell_connect()
{
    int fd = -1;
    char shell_cmd[SHELLCMD_BUF_SIZE] = {0,};
    struct sdb_version version;

    /* eshell */
    if(!get_platform_version(&version) && is_support_eshell(&version)) {
        int lines, columns;
        if(!get_screensize(&lines, &columns)) {
            snprintf(shell_cmd, sizeof(shell_cmd), "eshell:%d:%d", lines, columns);
            D("interactive shell : eshell command=%s\n", shell_cmd);
            fd = sdb_connect(shell_cmd);
        }
    }

    /* retry basic shell service */
    if(fd < 0){
        fd = sdb_connect("shell:");
    }

    return fd;
}

static int shell_connect_args(int argc, char ** argv)
{
    int fd = -1;
    char shell_cmd[SHELLCMD_BUF_SIZE] = {0,};

    snprintf(shell_cmd, sizeof(shell_cmd), "shell:%s", argv[1]);
    argc -= 2;
    argv += 2;
    while(argc-- > 0) {
        strncat(shell_cmd, " ", sizeof(shell_cmd) - strlen(shell_cmd) - 1);

        /* quote empty strings and strings with spaces */
        int quote = (**argv == 0 || strchr(*argv, ' '));
        if (quote)
            strncat(shell_cmd, "\"", sizeof(shell_cmd) - strlen(shell_cmd) - 1);
        strncat(shell_cmd, *argv++, sizeof(shell_cmd) - strlen(shell_cmd) - 1);
        if (quote)
            strncat(shell_cmd, "\"", sizeof(shell_cmd) - strlen(shell_cmd) - 1);
    }

    fd = sdb_connect(shell_cmd);

    return fd;
}

int shell(int argc, char ** argv) {
    int fd = -1;
    int sync_winsz_support = SYNCWINSZ_UNSUPPORTED;

    sync_winsz_support = check_syncwinsz_support();
    if(argc < 2) {
        fd = shell_connect();
    } else {
        fd = shell_connect_args(argc, argv);
    }

    if (fd < 0) {
        return 1;
    }

    sdb_execute_shell(fd, SDB_STDIN_ON, sync_winsz_support);
    sdb_close(fd);

    return 0;
}

int forkserver(int argc, char** argv) {
    if(!strcmp(argv[1], "server")) {
        if(argv[2] != NULL && !strcmp(argv[2], "--only-detect-tizen"))
            g_only_detect_tizen_device = 1;
        else
            g_only_detect_tizen_device = 0;
        int r = sdb_main(1, DEFAULT_SDB_PORT);
        return r;
    }
    else {
        print_error(SDB_MESSAGE_ERROR, F(ERR_COMMAND_MISSING_ARGUMENT, "fork-server"), NULL);
        return 1;
    }
}

static int is_support_debug_option(void){
    char full_cmd[16] = {0,};
    char cap_buffer[CAPBUF_SIZE] = {0,};
    uint16_t len = 0;
    int ret = -1;
    char* failmsg = NULL;

    snprintf(full_cmd, sizeof(full_cmd), "capability:");
    int fd = sdb_connect_getfailmsg(full_cmd, &failmsg);
    if (fd >= 0) {
        readx(fd, &len, sizeof(uint16_t));
        if (len > CAPBUF_SIZE-1) {
            len = CAPBUF_SIZE-1;
        }
        readx(fd, cap_buffer, len);
        sdb_close(fd);

        /* This routine is temporarily coded in a state that the app
         * protocol version design is not complete.
         * To suppurt 2.3.1 WC payment, this logic MUST be still remained.
         * This routine is also coded in sdblib. */
        ret = match_capability_key_value(cap_buffer, "sdbd_rootperm", "disabled");
        if (ret == 1) {
            return ret;
        }
    } else {
        D("This platform does not support the capability service.\n");
        if (failmsg != NULL) {
            D("sdb_connect() fail message : %s\n", failmsg);
            SAFE_FREE(failmsg);
        }
    }

    /* This routine is temporarily coded in a state that the app
     * protocol version design is not complete.
     * To suppurt 2.4 Emulator, this logic MUST be still remained.
     * This routine is also coded in sdblib. */
    /* try to check profile_command version */
    D("sdbd_rootperm is NOT available. try to check profile_command version\n");
    char buf[512] = {};

    const char* SHELL_GET_PROFILE_VER_CMD ="shell:/usr/bin/profile_command getversion";
    fd = sdb_connect(SHELL_GET_PROFILE_VER_CMD);

    if(fd < 0) {
        // default : not support -G option.
        return -1;
    }
    if (read_line(fd, buf, sizeof(buf)) > 0) {
        int major = 0;
        int minor = 0;
        if (sscanf(buf, "%d.%d", &major, &minor) == 2) {
            // major version number at least 4
            if (major >= 4) {
                ret = 1;
            }
        }
    }
    sdb_close(fd);

    return ret;
}

static int is_support_whitespace_pkgname(void){
    int supported = 0;
    struct sdb_version version;
    int ret = -1;

    ret = get_platform_version(&version);
    if(ret < 0) {
        // default : not support whitespace for package file name.
        return 0;
    }

    D("Platform version : %d.%d.%d\n", version.major, version.minor, version.patch);
    // version number at least 2.4.0
    if (version.major >= 3 || (version.major >= 2 && version.minor >=4)) {
        supported = 1;
    }

    return supported;
}

int install(int argc, char **argv) {
    char* srcpath = argv[1];
    const char* filename = sdb_dirstop(srcpath);

    char destination[PATH_MAX] = {0,};
    if(get_pkg_tmp_dir(destination, sizeof(destination)) < 0) {
        return 1;
    }

    if (filename) {
        filename++;
        strncat(destination, filename, PATH_MAX - 1 );
    } else {
        strncat(destination, srcpath, PATH_MAX - 1 );
    }

    D("Install path%s\n", destination);
    int tpk = get_pkgtype_file_name(srcpath);
    if (tpk == -1) {
        print_error(SDB_MESSAGE_ERROR, F(ERR_PACKAGE_TYPE_UNKNOWN, srcpath), NULL);
        return 1;
    }

    D("Push file: %s to %s\n", srcpath, destination);
    SYNC_INFO info = {
            .srcF = (FILE_FUNC*)&LOCAL_FILE_FUNC,
            .dstF = (FILE_FUNC*)&REMOTE_FILE_FUNC,
            .copied = 0,
            .skipped = 0,
            .total_bytes = 0,
            .tag = {'p', 'u', 's', 'h', 'e', 'd', '\0'},
    };

    fprintf(stdout,"%s\n", MSG_SYNC_SECURE_WARNING);
    if(do_sync_copy(srcpath, destination, &info, 0)) {
        return 1;
    }

    const char* SHELL_INSTALL_CMD = NULL;
    char full_cmd[PATH_MAX];

    if (is_support_debug_option() == 1) {
        SHELL_INSTALL_CMD ="shell:/usr/bin/pkgcmd -i -t %s -p \"%s\" -q -G";
    } else {
        SHELL_INSTALL_CMD ="shell:/usr/bin/pkgcmd -i -t %s -p \"%s\" -q";
    }

    if(tpk == 1) {
        snprintf(full_cmd, sizeof full_cmd, SHELL_INSTALL_CMD, "tpk", destination);
    }
    else if(tpk == 0){
        snprintf(full_cmd, sizeof full_cmd, SHELL_INSTALL_CMD, "wgt", destination);
    }
    else if(tpk == 2){
        snprintf(full_cmd, sizeof full_cmd, SHELL_INSTALL_CMD, "rpm", destination);
    }

    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    if(__sdb_command(full_cmd) < 0) {
        return 1;
    }

    const char* SHELL_REMOVE_CMD = "shell:/bin/rm -f \"%s\"";
    snprintf(full_cmd, sizeof full_cmd, SHELL_REMOVE_CMD, destination);
    D(COMMANDLINE_MSG_FULL_CMD, "remove", full_cmd);
    if(__sdb_command(full_cmd) < 0) {
        return 1;
    }

    return 0;
}

int uninstall(int argc, char **argv) {
    char* appid = argv[1];
    const char* SHELL_UNINSTALL_CMD ="shell:/usr/bin/pkgcmd -u -n %s -q";
    char full_cmd[PATH_MAX];
    int result = 0;

    snprintf(full_cmd, sizeof full_cmd, SHELL_UNINSTALL_CMD, appid);
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    result = __sdb_command(full_cmd);

    if(result < 0) {
        return 1;
    }

    return 0;
}

int get_capability(int argc, char ** argv) {
    char full_cmd[16] = {0,};
    char cap_buffer[CAPBUF_SIZE] = {0,};
    uint16_t len = 0;

    snprintf(full_cmd, sizeof(full_cmd), "capability:");
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    int fd = sdb_connect(full_cmd);

    if(fd >= 0) {
        readx(fd, &len, sizeof(uint16_t));
        if (len > CAPBUF_SIZE-1) {
            len = CAPBUF_SIZE-1;
        }
        readx(fd, cap_buffer, len);

        fprintf(stdout, "%s\n", cap_buffer);
        sdb_close(fd);
        return 0;
    }
    return 1;
}

static int get_pkg_tmp_dir_from_capability(char* pkg_tmp_dir, int len) {
    char cap_buffer[CAPBUF_SIZE] = {0,};
    const char* GET_CAPABILITY_CMD = "capability:";
    int fd = -1;
    int cap_data_size = 0;
    int ret = -1;
    char* failmsg = NULL;

    fd = sdb_connect_getfailmsg(GET_CAPABILITY_CMD, &failmsg);
    if(fd < 0) {
        D("This platform does not support the capability service.\n");
        if (failmsg != NULL) {
            D("sdb_connect() fail message : %s\n", failmsg);
            SAFE_FREE(failmsg);
        }
        return -1;
    }

    readx(fd, &cap_data_size, sizeof(uint16_t));
    if (cap_data_size > CAPBUF_SIZE-1) {
        cap_data_size = CAPBUF_SIZE-1;
    }
    readx(fd, cap_buffer, cap_data_size);
    sdb_close(fd);

    ret = parse_capability_key_value(cap_buffer, "sdk_toolpath", pkg_tmp_dir, len);
    if (ret > 0) {
        D("capability sdk_toolpath = %s\n", pkg_tmp_dir);

        if (!strncmp(pkg_tmp_dir, "unknown", 7)) {
            D("sdk_toolpath is not available value : %s\n", pkg_tmp_dir);
            ret = -1;
        } else {
            int dir_len = strlen(pkg_tmp_dir);
            if(dir_len > 0 && dir_len < len
                    && pkg_tmp_dir[dir_len -1] != '/' && pkg_tmp_dir[dir_len -1] != '\\') {
                pkg_tmp_dir[dir_len] = '/';
            }
            ret = 0;
        }
    }

    return ret;
}

static int get_pkg_tmp_dir_from_pkgcmd(char* pkg_tmp_dir, int len) {
    char pkgcmd_out_data[512] = {0,};
    const char* SHELL_GET_PKG_TMP_DIR_CMD ="shell:/usr/bin/pkgcmd -a | head -1 | awk '{print $5}'";
    int fd = -1;
    int ret = -1;

    fd = sdb_connect(SHELL_GET_PKG_TMP_DIR_CMD);
    if(fd < 0) {
        D("failed to get the package temporary path from pkgcmd\n");
        return -1;
    }

    if (read_line(fd, pkgcmd_out_data, sizeof(pkgcmd_out_data)) > 0) {
        D("\'pkgcmd -a\' result = %s\n", pkgcmd_out_data);
        append_file(pkg_tmp_dir, pkgcmd_out_data, "/tmp/", len);
        ret = 0;
    }

    sdb_close(fd);
    return ret;
}

// Get the package temporary path. Returns minus if exception happens.
static int get_pkg_tmp_dir(char* pkg_tmp_dir, int len){
    int ret = -1;

    ret = get_pkg_tmp_dir_from_capability(pkg_tmp_dir, len);
    if (ret < 0) {
        D("failed to get the package temporary path from capability\n");
        D("retry using the pkgcmd shell command.\n");
        ret = get_pkg_tmp_dir_from_pkgcmd(pkg_tmp_dir, len);
    }

    if (ret < 0) {
        print_error(SDB_MESSAGE_ERROR, ERR_PACKAGE_GET_TEMP_PATH_FAIL, NULL);
    } else {
        D("package tmp dir = %s\n", pkg_tmp_dir);
    }

    return ret;
}

// Returns 0 if pkg type is wgt. Returns 1 if pkg type is tpk. Returns minus if exception happens.
static int get_pkgtype_file_name(const char* file_name) {

    char* pkg_type;

    int result = -1;

    pkg_type = strrchr(file_name, '.');
    if (pkg_type != NULL) {
        pkg_type++;
        if(!strcmp(pkg_type, "wgt")) {
            result = 0;
        }
        else if(!strcmp(pkg_type, "tpk")) {
            result = 1;
        }
        else if(!strcmp(pkg_type, "rpm")) {
                  result = 2;
              }
    }

    return result;
}

/*
 * kill gdbserver if running
 */

//LCOV_EXCL_START
static int kill_gdbserver_if_running(const char* process_cmd) {
    char cmd[512] = {};
    char buf[512] = {};

    // hopefully, it is not going to happen, but check executable gdbserver is existed
    snprintf(cmd, sizeof(cmd), "shell:/usr/bin/da_command process | grep '%s' | grep -v grep | wc -l", process_cmd);
    int result = sdb_connect(cmd);

    if(result < 0) {
        return -1;
    }
    if (read_line(result, buf, sizeof(buf)) < 0) {
        sdb_close(result);
        return -1;
    }
    if(memcmp(buf, "0", 1)) {
/*
        // TODO: check cmd return code
        snprintf(cmd, sizeof(cmd), "shell:/usr/bin/da_command killapp '%s'", process_cmd);
        result = sdb_connect(cmd);
        if (read_line(result, buf, sizeof(buf)) < 0) {
            sdb_close(result);
            return -1;
        }
*/
    }
    sdb_close(result);
    return 1;
}
//LCOV_EXCL_STOP

static void __inline__ format_host_command(char* buffer, size_t  buflen, const char* command, transport_type ttype, const char* serial)
{
    char prefix[NAME_MAX];
    get_host_prefix(prefix, NAME_MAX, ttype, serial, host);
    snprintf(buffer, buflen, "%s%s", prefix, command);
}


/*
 * returns -1 if gdbserver exists
 */
//LCOV_EXCL_START
static int verify_gdbserver_exist() {
    char cmd[512] = {};
    char buf[512] = {};

    snprintf(cmd, sizeof(cmd), "shell:%s/gdbserver/gdbserver --version 1>/dev/null", SDK_TOOL_PATH);
    int result = sdb_connect(cmd);

    if(result < 0) {
        sdb_close(result);
        return -1;
    }
    if (read_line(result, buf, sizeof(buf)) > 0) {
        print_error(SDB_MESSAGE_ERROR, buf, NULL);
        sdb_close(result);
        return -1;
    }
    sdb_close(result);
    return result;
}
//LCOV_EXCL_STOP

int get_boot(int argc, char ** argv) {
    char full_cmd[20];
    snprintf(full_cmd, sizeof(full_cmd), "boot:");
    D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);
    int fd = sdb_connect(full_cmd);

    if (fd >= 0) {
        read_and_dump(fd);
        sdb_close(fd);
        return 0;
    }
    return 1;
}

#ifdef SUPPORT_ENCRYPT
/* 
desc. : capability를 통한 encryption support check
parameter : 
ret. :  1 : if current device support encryption
*/
int check_encryption_support() { 
    char full_cmd[16] = {0,};
    char cap_buffer[CAPBUF_SIZE] = {0,};
    uint16_t len = 0;
    int supported = 0;
    int fd = -1;
    char* failmsg = NULL;
    int ret;

    snprintf(full_cmd, sizeof(full_cmd), "capability:");
    fd = sdb_connect_getfailmsg(full_cmd, &failmsg);
    if (fd >= 0) {
        readx(fd, &len, sizeof(uint16_t));
        if (len > CAPBUF_SIZE-1) {
            len = CAPBUF_SIZE-1;
        }
        readx(fd, cap_buffer, len);
        sdb_close(fd);

        ret = match_capability_key_value(cap_buffer, "encryption_support", "enabled");
        if (ret == 1) {
            supported = 1;
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

/* 
encryption command function
return 0 if command succeed
return 1 otherwise
*/
int encryption(int argc, char ** argv)
{
	char *tmp;
	char full_cmd[PATH_MAX] = {0, };
	char prefix[NAME_MAX] = {0, };

    // check whether sdbd support encryption feature or not
	if(check_encryption_support() == 0) {
        printf("This feature is not supported by current devices\n");
	} else {
        // prefix = host-any:
		get_host_prefix(prefix, NAME_MAX, target_ttype, target_serial, host);

        // ex) host-any:encryption:on
		snprintf(full_cmd, sizeof(full_cmd), "%sencryption:%s", prefix, argv[1]); 

		D(COMMANDLINE_MSG_FULL_CMD, argv[0], full_cmd);

        // use sdb_query because encryption command is not remote command
		tmp = sdb_query(full_cmd);

		if(tmp) {
			printf("%s", tmp);
			return 0;
		} 
	}

    return 1;
}
#endif
