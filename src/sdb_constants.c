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

#include "sdb_constants.h"

    const char* SDB_LAUNCH_SCRIPT = "/usr/sbin/sdk_launch";
    const char* HELP_APPEND_STR = "                            ";
    const int HELP_DESCRIPTION_STRING_WIDTH = 52;

    const char* EMPTY_STRING = "";
    const char* WHITE_SPACE = " ";
    const char* QUOTE_CHAR = " \"\\()";

    const char* PREFIX_HOST = "host:";
    const char* PREFIX_HOST_ANY = "host-any:";
    const char* PREFIX_HOST_USB = "host-usb:";
    const char* PREFIX_HOST_LOCAL = "host-local:";
    const char* PREFIX_HOST_SERIAL = "host-serial:";

    const char* PREFIX_TRANSPORT_ANY = "host:transport-any";
    const char* PREFIX_TRANSPORT_USB = "host:transport-usb";
    const char* PREFIX_TRANSPORT_LOCAL = "host:transport-local";
    const char* PREFIX_TRANSPORT_SERIAL = "host:transport:";

    const char* COMMANDLINE_MSG_FULL_CMD = "full command of %s: %s\n";
    const char* COMMANDLINE_OPROFILE_NAME = "oprofile";
    const int COMMANDLINE_OPROFILE_MAX_ARG = -1;
    const int COMMANDLINE_OPROFILE_MIN_ARG = 0;

    const char* COMMANDLINE_PROFILE_NAME = "profile";
    const int COMMANDLINE_PROFILE_MAX_ARG = -1;
    const int COMMANDLINE_PROFILE_MIN_ARG = 0;

    const char* COMMANDLINE_DA_NAME = "da";
    const int COMMANDLINE_DA_MAX_ARG = -1;
    const int COMMANDLINE_DA_MIN_ARG = 0;

    const char* COMMANDLINE_LAUNCH_NAME = "launch";
    const int COMMANDLINE_LAUNCH_MAX_ARG = -1;
    const int COMMANDLINE_LAUNCH_MIN_ARG = 0;

    const char* COMMANDLINE_DEVICES_NAME = "devices";
    const char* COMMANDLINE_DEVICES_DESC[] = {
            "Display a list of all connected target instances."
    };
    const int COMMANDLINE_DEVICES_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_DEVICES_DESC, char*);
    const int COMMANDLINE_DEVICES_MAX_ARG = 0;
    const int COMMANDLINE_DEVICES_MIN_ARG = 0;

    const char* COMMANDLINE_DISCONNECT_NAME = "disconnect";
    const char* COMMANDLINE_DISCONNECT_DESC[] = {
            "Disconnect from a TCP/IP device. By default, the port 26101 is used if there is no specified port number. If you use this command with no additional arguments, all connected TCP/IP devices are disconnected."
    };
    const int COMMANDLINE_DISCONNECT_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_DISCONNECT_DESC, char*);
    const char* COMMANDLINE_DISCONNECT_ARG_DESC = "[<ip>[:<port>]]";
    const int COMMANDLINE_DISCONNECT_MAX_ARG = 1;
    const int COMMANDLINE_DISCONNECT_MIN_ARG = 0;

    const char* COMMANDLINE_CONNECT_NAME = "connect";
    const char* COMMANDLINE_CONNECT_DESC[] = {
            "Connect to a target through TCP/IP."
    };
    const int COMMANDLINE_CONNECT_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_CONNECT_DESC, char*);
    const char* COMMANDLINE_CONNECT_ARG_DESC = "[<ip>[:<port>]]";
    const int COMMANDLINE_CONNECT_MAX_ARG = 1;
    const int COMMANDLINE_CONNECT_MIN_ARG = 1;

    const char* COMMANDLINE_DEVICE_CON_NAME = "device_con";
    const char* COMMANDLINE_DEVICE_CON_DESC[] = {
            "connect to a remote device"
    };
    const int COMMANDLINE_DEVICE_CON_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_DEVICE_CON_DESC, char*);
    const char* COMMANDLINE_DEVICE_CON_ARG_DESC = "<host> <device serial-number>";
    const int COMMANDLINE_DEVICE_CON_MAX_ARG = 2;
    const int COMMANDLINE_DEVICE_CON_MIN_ARG = 2;

    const char* COMMANDLINE_GSERIAL_NAME = "get-serialno";
    const char* COMMANDLINE_GSERIAL_DESC[] = {
            "Print the serial number for connecting the target device."
    };
    const int COMMANDLINE_GSERIAL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_GSERIAL_DESC, char*);
    const int COMMANDLINE_GSERIAL_MAX_ARG = 0;
    const int COMMANDLINE_GSERIAL_MIN_ARG = 0;

    const char* COMMANDLINE_GSTATE_NAME = "get-state";
    const char* COMMANDLINE_GSTATE_DESC[] = {
            "Print the connection status with the target device: device/offline/locked."
    };
    const int COMMANDLINE_GSTATE_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_GSTATE_DESC, char*);
    const int COMMANDLINE_GSTATE_MAX_ARG = 0;
    const int COMMANDLINE_GSTATE_MIN_ARG = 0;

    const char* COMMANDLINE_ROOT_NAME = "root";
    const char* COMMANDLINE_ROOT_DESC[] = {
            "Switch between the root and developer account mode. The 'on' value sets the root mode and the 'off' value sets the developer account mode."
    };
    const int COMMANDLINE_ROOT_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_ROOT_DESC, char*);
    const char* COMMANDLINE_ROOT_ARG_DESC = "{on|off}";
    const int COMMANDLINE_ROOT_MAX_ARG = 1;
    const int COMMANDLINE_ROOT_MIN_ARG = 1;

    const char* COMMANDLINE_SWINDOW_NAME = "status-window";
    const char* COMMANDLINE_SWINDOW_DESC[] = {
            "Print the connection status for a specified device continuously."
    };
    const int COMMANDLINE_SWINDOW_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_SWINDOW_DESC, char*);
    const int COMMANDLINE_SWINDOW_MAX_ARG = 0;
    const int COMMANDLINE_SWINDOW_MIN_ARG = 0;

    const char* COMMANDLINE_SSERVER_NAME = "start-server";
    const char* COMMANDLINE_SSERVER_DESC[] = {
            "Start the server. If [--only-detect-tizen] is specified, the SDB detects only Tizen devices."
    };
    const int COMMANDLINE_SSERVER_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_SSERVER_DESC, char*);
    const char* COMMANDLINE_SSERVER_ARG_DESC = "[--only-detect-tizen]";
    const int COMMANDLINE_SSERVER_MAX_ARG = 1;
    const int COMMANDLINE_SSERVER_MIN_ARG = 0;

    const char* COMMANDLINE_KSERVER_NAME = "kill-server";
    const char* COMMANDLINE_KSERVER_DESC[] = {
            "Stop the running server."
    };
    const int COMMANDLINE_KSERVER_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_KSERVER_DESC, char*);
    const int COMMANDLINE_KSERVER_MAX_ARG = 0;
    const int COMMANDLINE_KSERVER_MIN_ARG = 0;

    const char* COMMANDLINE_HELP_NAME = "help";
    const char* COMMANDLINE_HELP_DESC[] = {
            "Show the help message."
    };
    const int COMMANDLINE_HELP_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_HELP_DESC, char*);

    const char* COMMANDLINE_VERSION_NAME = "version";
    const char* COMMANDLINE_VERSION_DESC[] = {
            "Show the version number."
    };
    const int COMMANDLINE_VERSION_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_VERSION_DESC, char*);
    const int COMMANDLINE_VERSION_MAX_ARG = 0;
    const int COMMANDLINE_VERSION_MIN_ARG = 0;

    const char* COMMANDLINE_DLOG_NAME = "dlog";
    const char* COMMANDLINE_DLOG_DESC[] = {
            "Monitor the content of the device log buffers.\n[-f <filename>] writes the log to the <filename> file. The default file is stdout.\n[-r <Kbytes>] rotates the log file every <Kbytes> of output. The default value is 16. This option also requires the -f option.\n[-n <count>] sets the maximum number of rotated logs to <count>. The default value is 4. This option also requires the -r option.\n[-v <format>] sets the output format (brief/process/tag/thread/raw/time/long) for log messages. The default value of <format> is 'brief'."
    };
    const int COMMANDLINE_DLOG_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_DLOG_DESC, char*);
    const char* COMMANDLINE_DLOG_ARG_DESC = "[-f <filename>] [-r <Kbytes>] [-n <count>] [-v <format>]";
    const int COMMANDLINE_DLOG_MAX_ARG = -1;
    const int COMMANDLINE_DLOG_MIN_ARG = 0;

    const char* COMMANDLINE_FORWARD_NAME = "forward";
    const char* COMMANDLINE_FORWARD_DESC[] = {
            "Set up requests' arbitrary port forwarding from the host's local port to the target's remote port."
    };
    const int COMMANDLINE_FORWARD_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_FORWARD_DESC, char*);
    const char* COMMANDLINE_FORWARD_ARG_DESC = "<local> <remote>";
    const int COMMANDLINE_FORWARD_MAX_ARG = 2;
    const int COMMANDLINE_FORWARD_MIN_ARG = 1;

    const char* COMMANDLINE_FORWARD_LIST_NAME = "forward --list";
    const char* COMMANDLINE_FORWARD_LIST_DESC[] = {
            "Display a list of all forwarded socket connections."
    };
    const int COMMANDLINE_FORWARD_LIST_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_FORWARD_LIST_DESC, char*);
    const int COMMANDLINE_FORWARD_LIST_MAX_ARG = 0;
    const int COMMANDLINE_FORWARD_LIST_MIN_ARG = 0;

    const char* COMMANDLINE_FORWARD_REMOVE_NAME = "forward --remove";
    const char* COMMANDLINE_FORWARD_REMOVE_DESC[] = {
            "Remove the <local> forward socket connection."
    };
    const int COMMANDLINE_FORWARD_REMOVE_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_FORWARD_REMOVE_DESC, char*);
    const char* COMMANDLINE_FORWARD_REMOVE_ARG_DESC = "<local>";
    const int COMMANDLINE_FORWARD_REMOVE_MAX_ARG = 1;
    const int COMMANDLINE_FORWARD_REMOVE_MIN_ARG = 1;

    const char* COMMANDLINE_FORWARD_REMOVE_ALL_NAME = "forward --remove-all";
    const char* COMMANDLINE_FORWARD_REMOVE_ALL_DESC[] = {
            "Remove all forwarded socket connections."
    };
    const int COMMANDLINE_FORWARD_REMOVE_ALL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_FORWARD_REMOVE_ALL_DESC, char*);
    const int COMMANDLINE_FORWARD_REMOVE_ALL_MAX_ARG = 0;
    const int COMMANDLINE_FORWARD_REMOVE_ALL_MIN_ARG = 0;

    const char* COMMANDLINE_FORWARDLIST_NAME = "forward-list";
    const char* COMMANDLINE_FORWARDLIST_DESC[] = {
            "Display a list of all forwarded socket connections."
    };
    const int COMMANDLINE_FORWARDLIST_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_FORWARDLIST_DESC, char*);
    const int COMMANDLINE_FORWARDLIST_MAX_ARG = 0;
    const int COMMANDLINE_FORWARDLIST_MIN_ARG = 0;

    const char* COMMANDLINE_PUSH_NAME = "push";
    const char* COMMANDLINE_PUSH_DESC[] = {
            "Copy a file or directory recursively from the host computer to the target."
    };
    const int COMMANDLINE_PUSH_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_PUSH_DESC, char*);
    const char* COMMANDLINE_PUSH_ARG_DESC = "<local> <remote> [--with-utf8]";
    const int COMMANDLINE_PUSH_MAX_ARG = -1;
    const int COMMANDLINE_PUSH_MIN_ARG = 2;

    const char* COMMANDLINE_PULL_NAME = "pull";
    const char* COMMANDLINE_PULL_DESC[] = {
            "Copy a file or directory recursively from the target to the host computer."
    };
    const int COMMANDLINE_PULL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_PULL_DESC, char*);
    const char* COMMANDLINE_PULL_ARG_DESC = "<remote> [<local>]";
    const int COMMANDLINE_PULL_MAX_ARG = -2;
    const int COMMANDLINE_PULL_MIN_ARG = 1;

    const char* COMMANDLINE_SHELL_NAME = "shell";
    const char* COMMANDLINE_SHELL_DESC[] = {
           "Launch the shell on the target instance if the <command> is not specified. If the <command> is specified, this runs the <command> without entering the SDB remote shell on the target instance."
    };
    const int COMMANDLINE_SHELL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_SHELL_DESC, char*);
    const char* COMMANDLINE_SHELL_ARG_DESC = "[command]";
    const int COMMANDLINE_SHELL_MAX_ARG = -1;
    const int COMMANDLINE_SHELL_MIN_ARG = 0;

    const char* COMMANDLINE_INSTALL_NAME = "install";
    const char* COMMANDLINE_INSTALL_DESC[] = {
            "Push the tpk package file in the <pkg_path> to the device and install it."
    };
    const int COMMANDLINE_INSTALL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_INSTALL_DESC, char*);
    const char* COMMANDLINE_INSTALL_ARG_DESC = "<pkg_path>";
    const int COMMANDLINE_INSTALL_MAX_ARG = 1;
    const int COMMANDLINE_INSTALL_MIN_ARG = 1;

    const char* COMMANDLINE_UNINSTALL_NAME = "uninstall";
    const char* COMMANDLINE_UNINSTALL_DESC[] = {
            "Uninstall the application from the device by using its pkg-id. The <pkg_id> is a 10-digit unique identifier for the application."
    };
    const int COMMANDLINE_UNINSTALL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_UNINSTALL_DESC, char*);
    const char* COMMANDLINE_UNINSTALL_ARG_DESC = "<pkg_id>";
    const int COMMANDLINE_UNINSTALL_MAX_ARG = 1;
    const int COMMANDLINE_UNINSTALL_MIN_ARG = 1;

    const char* COMMANDLINE_FORKSERVER_NAME = "fork-server";
    const int COMMANDLINE_FORKSERVER_MAX_ARG = 2;
    const int COMMANDLINE_FORKSERVER_MIN_ARG = 1;

    const char* COMMANDLINE_CAPABILITY_NAME = "capability";
    const int COMMANDLINE_CAPABILITY_MAX_ARG = 0;
    const int COMMANDLINE_CAPABILITY_MIN_ARG = 0;

    const char* COMMANDLINE_BOOT_NAME = "boot";
    const int COMMANDLINE_BOOT_MAX_ARG = 0;
    const int COMMANDLINE_BOOT_MIN_ARG = 0;

    const char* COMMANDLINE_SERIAL_SHORT_OPT = "s";
    const char* COMMANDLINE_SERIAL_LONG_OPT = "serial";
    const char* COMMANDLINE_SERIAL_DESC[] = {
            "Send the <command> to a target through <serial number>."
    };
    const int COMMANDLINE_SERIAL_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_SERIAL_DESC, char*);
    const char* COMMANDLINE_SERIAL_ARG_DESC = "<serial_number>";
    const int COMMANDLINE_SERIAL_HAS_ARG = 1;

    const char* COMMANDLINE_EMULATOR_SHORT_OPT = "e";
    const char* COMMANDLINE_EMULATOR_LONG_OPT = "emulator";
    const char* COMMANDLINE_EMULATOR_DESC[] = {
            "Send the <command> to a running emulator instance and returns an error if there are other instances."
    };
    const int COMMANDLINE_EMULATOR_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_EMULATOR_DESC, char*);
    const int COMMANDLINE_EMULATOR_HAS_ARG = 0;

    const char* COMMANDLINE_DEVICE_SHORT_OPT = "d";
    const char* COMMANDLINE_DEVICE_LONG_OPT = "device";
    const char* COMMANDLINE_DEVICE_DESC[] = {
            "Send the <command> to a connected device and returns an error if there are other devices."
    };
    const int COMMANDLINE_DEVICE_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_DEVICE_DESC, char*);
    const int COMMANDLINE_DEVICE_HAS_ARG = 0;

    const char* COMMANDLINE_ERROR_ARG_MISSING = "argument %s is missing for command %s";

    const char* STATE_OFFLINE = "offline";
    const char* STATE_BOOTLOADER = "bootloader";
    const char* STATE_DEVICE = "device";
    const char* STATE_HOST = "host";
    const char* STATE_RECOVERY = "recovery";
    const char* STATE_SIDELOAD = "sideload";
    const char* STATE_NOPERM = "no permissions";
    const char* STATE_LOCKED = "locked";
    const char* STATE_UNKNOWN = "unknown";
    const char* STATE_SUSPENDED = "suspended";
    const char* STATE_UNAUTHORIZED = "unauthorized";

#ifdef SUPPORT_ENCRYPT
    const char* COMMANDLINE_ENCRYPTION_NAME = "encryption";
	const char* COMMANDLINE_ENCRYPTION_ARG_DESC = "{on|off|status}";
	const char* COMMANDLINE_ENCRYPTION_DESC[] = {
            "Set encryption modes for got/sent data."
    };
    const int COMMANDLINE_ENCRYPTION_DESC_SIZE = GET_ARRAY_SIZE(COMMANDLINE_ENCRYPTION_DESC, char*);
    const int COMMANDLINE_ENCRYPTION_MAX_ARG = 1;
    const int COMMANDLINE_ENCRYPTION_MIN_ARG = 1;
#endif
