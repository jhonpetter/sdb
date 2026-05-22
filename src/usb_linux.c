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
#include <ctype.h>
#include <dirent.h>
#if SDB_USB_INOTIFY
#include <sys/inotify.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <linux/usb/ch9.h>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#if HAVE_UDEV
#include <libudev.h>
#endif

#include "utils.h"
#include "fdevent.h"
#include "strutils.h"
#include "sdb_usb.h"
#include "log.h"
#include "transport.h"

#define   TRACE_TAG  TRACE_USB
#define   DEBUG_URB  0
#define   LOG_DEBUG_URB(args...)  do { if (DEBUG_URB) LOG_DEBUG(args); } while (0)

#define   URB_TRANSFER_TIMEOUT   0
#define   USB_DEV_BASE_PATH     "/dev/bus/usb"
#if SDB_USB_INOTIFY
#define   INOTIFY_EVENT_SIZE    (sizeof(struct inotify_event))
#define   INOTIFY_BUF_SIZE      (4 * (INOTIFY_EVENT_SIZE + 16))
#define   USB_MAXBUS            64
#endif

SDB_MUTEX_DEFINE( usb_lock);

LIST_NODE* usb_list = NULL;

#define SDB_URB_TYPE_READ   0
#define SDB_URB_TYPE_WRITE  1
struct usb_handle {
    LIST_NODE* node;

    char unique_node_path[PATH_MAX + 1];
    int node_fd;
    unsigned char end_point[2]; // 0:in, 1:out
    int interface;

    struct usbdevfs_urb urb_in;
    struct usbdevfs_urb urb_out;
};

static int get_usb_device_serial_number(int usb_fd, __u8 serial_index, char* serial)
{
    struct usbdevfs_ctrltransfer  ctrl;
    __u16 buffer[128];
    __u16 languages[128];
    int i, result;
    int languageCount = 0;
    int ret = 0;

    memset(languages, 0, sizeof(languages));
    memset(&ctrl, 0, sizeof(ctrl));

    // read list of supported languages
    ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
    ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
    ctrl.wValue = (USB_DT_STRING << 8) | 0;
    ctrl.wIndex = 0;
    ctrl.wLength = sizeof(languages);
    ctrl.data = languages;
    ctrl.timeout = 1000;

    result = ioctl(usb_fd, USBDEVFS_CONTROL, &ctrl);
    if (result > 0)
        languageCount = (result - 2) / 2;

    LOG_DEBUG("languageCount=%d\n", languageCount);

    for (i = 1; i <= languageCount; i++) {
        memset(buffer, 0, sizeof(buffer));
        memset(&ctrl, 0, sizeof(ctrl));

        ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
        ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
        ctrl.wValue = (USB_DT_STRING << 8) | serial_index;
        ctrl.wIndex = __le16_to_cpu(languages[i]);
        ctrl.wLength = sizeof(buffer);
        ctrl.data = buffer;
        ctrl.timeout = 1000;

        result = ioctl(usb_fd, USBDEVFS_CONTROL, &ctrl);
        if (result > 0) {
            int i;
            // skip first word, and copy the rest to the serial string, changing shorts to bytes.
            result /= 2;
            for (i = 1; i < result; i++)
                serial[i - 1] = __le16_to_cpu(buffer[i]);
            serial[i - 1] = 0;

            ret = 1;
            break;
        }
    }

    LOG_DEBUG("serial=%s\n", serial);

    return ret;
}

int register_device(const char* node, const char* serial) {
    int fd;
    unsigned char device_desc[4096];
    unsigned char* desc_current_ptr = NULL;
    int is_registered = 0;

    if (node == NULL) {
        return -1;
    }
    if (is_device_registered(node)) {
        LOG_DEBUG("already registered device: %s\n", node);
        return -1;
    }
    if ((fd = open(node, O_RDWR)) < 0) {
        LOG_DEBUG("failed to open usb node %s (%s)\n", node, strerror(errno));
        return -1;
    }

    int length;
    if ((length = read(fd, device_desc, sizeof(device_desc))) < 0) {
        LOG_DEBUG("failed to read usb node %s (%s)\n", node, strerror(errno));
        close(fd);
        return -1;
    }

    desc_current_ptr = device_desc;

    // get device descriptor from head first
    struct usb_device_descriptor* usb_dev =
            (struct usb_device_descriptor*) desc_current_ptr;

    if (USB_DT_DEVICE_SIZE != usb_dev->bLength) {
        LOG_DEBUG("failed to get usb device descriptor\n");
        close(fd);
        return -1;
    }

    // move to get device config
    desc_current_ptr += usb_dev->bLength;

    // enumerate all available configuration descriptors
    int i = 0;
    for (i = 0; i < usb_dev->bNumConfigurations; i++) {
        struct usb_config_descriptor* usb_config =
                (struct usb_config_descriptor *) desc_current_ptr;
        if (USB_DT_CONFIG_SIZE != usb_config->bLength) {
            LOG_DEBUG("failed to get usb config descriptor\n");
            break;
        }
        desc_current_ptr += usb_config->bLength;

        unsigned int wTotalLength = usb_config->wTotalLength;
        unsigned int wSumLength = usb_config->bLength;

        if (usb_config->bNumInterfaces < 1) {
            LOG_DEBUG("there is no interfaces\n");
            break;
        }

        while (wSumLength < wTotalLength) {
            int bLength = desc_current_ptr[0];
            int bType = desc_current_ptr[1];

            struct usb_interface_descriptor* usb_interface =
                    (struct usb_interface_descriptor *) desc_current_ptr;

            platform_type platform= get_platform_type(usb_dev->idVendor,
                                usb_interface->bInterfaceClass,
                                usb_interface->bInterfaceSubClass,
                                usb_interface->bInterfaceProtocol);
            if ((platform != PLATFORM_UNKNOWN)
                    && (USB_DT_INTERFACE_SIZE == bLength
                            && USB_DT_INTERFACE == bType
                            && 2 == usb_interface->bNumEndpoints)) {
                desc_current_ptr += usb_interface->bLength;
                wSumLength += usb_interface->bLength;
                struct usb_endpoint_descriptor *endpoint1 =
                        (struct usb_endpoint_descriptor *) desc_current_ptr;
                desc_current_ptr += endpoint1->bLength;
                wSumLength += endpoint1->bLength;
                struct usb_endpoint_descriptor *endpoint2 =
                        (struct usb_endpoint_descriptor *) desc_current_ptr;
                unsigned char endpoint_in;
                unsigned char endpoint_out;
                unsigned char interface = usb_interface->bInterfaceNumber;

                if(platform == PLATFORM_ANDROID) {
					int bConfigurationValue = 2;
					int n = ioctl(fd, USBDEVFS_SETCONFIGURATION,
												&bConfigurationValue);
					if (n != 0) {
						LOG_DEBUG("check kernel is supporting %dth configuration\n", bConfigurationValue);
					}
                } else {
                    if(usb_dev->bNumConfigurations > 1) {
                        int bConfigurationValue = i + 1;

                        int n = ioctl(fd, USBDEVFS_RESET);
                        if (n != 0) {
                            LOG_DEBUG("usb reset failed\n");
                        }
                        n = ioctl(fd, USBDEVFS_SETCONFIGURATION,
                                &bConfigurationValue);
                        if (n != 0) {
                            LOG_DEBUG("check kernel is supporting %dth configuration\n", bConfigurationValue);
                        } else {
                            LOG_DEBUG("set configuration to %d\n", bConfigurationValue);
                        }

                        n = ioctl(fd, USBDEVFS_CLAIMINTERFACE, &interface);
                        if (n != 0) {
                            LOG_DEBUG("usb claim failed\n");
                        }
                    } else {
                        LOG_DEBUG("total number of configuration is %d, no need to set configurations\n", usb_dev->bNumConfigurations);
                    }
                }

                // find in/out endpoint address
                if ((endpoint1->bEndpointAddress & USB_ENDPOINT_DIR_MASK)
                        == USB_DIR_IN) {
                    endpoint_in = endpoint1->bEndpointAddress;
                    endpoint_out = endpoint2->bEndpointAddress;
                } else {
                    endpoint_out = endpoint1->bEndpointAddress;
                    endpoint_in = endpoint2->bEndpointAddress;
                }
                // for now i can agree to register usb
                {
                    usb_handle* usb = NULL;
                    usb = calloc(1, sizeof(usb_handle));

                    if (usb == NULL) {
                        break;
                    }
                    usb->node_fd = fd;
                    usb->interface = usb_interface->bInterfaceNumber;
                    usb->end_point[0] = endpoint_in;
                    usb->end_point[1] = endpoint_out;

                    char usb_serial[MAX_SERIAL_NAME] = { 0, };

                    if (serial != NULL) {
                        s_strncpy(usb_serial, serial, sizeof(usb_serial));
                    } else {
                        if(!get_usb_device_serial_number(fd, usb_dev->iSerialNumber, usb_serial)) {
                            snprintf(usb_serial, sizeof(usb_serial), "%s", "unknown");
                        }
                    }
                    s_strncpy(usb->unique_node_path, node,
                            sizeof(usb->unique_node_path));

                    sdb_mutex_lock(&usb_lock, "usb register locked");
                    usb->node = prepend(&usb_list, usb);
                    LOG_DEBUG("-register new device (in: %04x, out: %04x) from %s\n", usb->end_point[0], usb->end_point[1], node);

                    is_registered = 1;
                    register_usb_transport(usb, usb_serial, platform);
                    sdb_mutex_unlock(&usb_lock, "usb register unlocked");
                }
                desc_current_ptr += endpoint2->bLength;
                wSumLength += endpoint2->bLength;

            } else {
                wSumLength += usb_interface->bLength;
                desc_current_ptr += usb_interface->bLength;
            }
        }
    }
    if (is_registered == 0) {
        close(fd);
    }
    return 0;
}

#if HAVE_UDEV
static void usb_plugged(struct udev_device *dev) {
    if (udev_device_get_devnode(dev) != NULL) {
        register_device(udev_device_get_devnode(dev),
                udev_device_get_sysattr_value(dev, "serial"));
    }
}

static void usb_unplugged(struct udev_device *dev) {
    LOG_INFO("check device is removed from the list\n");
}

int usb_register_callback(int msec) {
    struct udev *udev;
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices, *dev_list_entry;
    struct udev_device *dev;

    struct udev_monitor *mon;
    int fd;

    // Create the udev object
    udev = udev_new();
    if (!udev) {
        LOG_DEBUG("Can't create udev\n");
        exit(1);
    }

    // Set up a monitor to monitor hidraw devices
    mon = udev_monitor_new_from_netlink(udev, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(mon, "usb", "usb_device");
    udev_monitor_enable_receiving(mon);

    // Get the file descriptor (fd) for the monitor. This fd will get passed to select()
    fd = udev_monitor_get_fd(mon);

    // Create a list of the devices in the 'usb' subsystem.
    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "usb");
    udev_enumerate_scan_devices(enumerate);

    devices = udev_enumerate_get_list_entry(enumerate);

    LOG_DEBUG("doing lsusb to find tizen devices\n");
    udev_list_entry_foreach(dev_list_entry, devices) {
        const char *path;

        path = udev_list_entry_get_name(dev_list_entry);
        dev = udev_device_new_from_syspath(udev, path);
        usb_plugged(dev);
        udev_device_unref(dev);

    }
    // Free the enumerator object
    udev_enumerate_unref(enumerate);
    LOG_DEBUG("done lsusb to find tizen devices\n");
    while (1) {
        fd_set fds;
        struct timeval tv;
        int ret;

        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;

        ret = select(fd + 1, &fds, NULL, NULL, &tv);

        if (ret > 0 && FD_ISSET(fd, &fds)) {
            dev = udev_monitor_receive_device(mon);
            if (dev) {
                if (!strcmp("add", udev_device_get_action(dev))) {
                    usb_plugged(dev);
                } else {
                    usb_unplugged(dev);
                }
                udev_device_unref(dev);
            } else {
                LOG_DEBUG("failed to get noti from udev monitor\n");
            }
        }
        LOG_DEBUG("USB register call back start (try sleep) \n");
        usleep(msec);
    }
    udev_unref(udev);

    return 0;
}
#endif

int is_device_registered(const char *unique_node_path) {
    int r = 0;
    sdb_mutex_lock(&usb_lock, "usb registering locked");

    LIST_NODE* curptr = usb_list;
    while (curptr != NULL) {
        usb_handle *usb = curptr->data;
        if (!strcmp(usb->unique_node_path, unique_node_path)) {
            r = 1;
            break;
        }
        curptr = curptr->next_ptr;
    }

    sdb_mutex_unlock(&usb_lock, "usb registering unlocked");
    return r;
}

static inline int is_usbdevname(const char* name) {
    while (*name) {
        if (!isdigit(*name++))
            return 0;
    }
    return 1;
}

static void find_usb_device(const char* base) {
    DIR *busdir = NULL;
    DIR *devdir = NULL;
    struct dirent *de = NULL;
    char busname[32] = {0,};
    char devname[32] = {0,};

    busdir = opendir(base);
    if (!busdir) {
        LOG_ERROR("failed to opendir : %s\n", base);
        return;
    }

    while ((de = readdir(busdir)) != NULL) {
        if (!is_usbdevname(de->d_name)) {
            LOG_DEBUG("badname : %s\n", de->d_name);
            continue;
        }

        snprintf(busname, sizeof(busname), "%s/%s", base, de->d_name);
        LOG_DEBUG("usb busname: %s\n", busname);

        devdir = opendir(busname);
        if (devdir == NULL) {
            LOG_ERROR("failed to opendir : %s\n", base);
            continue;
        }

        while ((de = readdir(devdir)) != NULL) {
            if (!is_usbdevname(de->d_name)) {
                LOG_DEBUG("badname : %s\n", de->d_name);
                continue;
            }

            snprintf(devname, sizeof(devname), "%s/%s", busname, de->d_name);
            LOG_DEBUG("usb devname=%s\n", devname);

            register_device(devname, NULL);
        }

        closedir(devdir);
    }

    closedir(busdir);
}

static void poll_usb_device() {
    LOG_DEBUG("polling usb device directory. (%s)\n", USB_DEV_BASE_PATH);
    while (1) {
        find_usb_device(USB_DEV_BASE_PATH);
        sleep(1);
    }
}

#if SDB_USB_INOTIFY
static inline void remove_watches(int inotify_fd, int watch_cnt, int* watch_fds) {
    int i = 0;
    for (i = 0; i < watch_cnt; i++)
        inotify_rm_watch(inotify_fd, watch_fds[i]);
}

static int inotify_add_watch_usb_bus(const char* base, int inotify_fd, int* watch_fds) {
    DIR *busdir = NULL;
    struct dirent *de = NULL;
    char busname[32] = {0,};
    int bus_cnt = 0;

    busdir = opendir(base);
    if (!busdir) {
        LOG_ERROR("failed to opendir : %s\n", base);
        return -1;
    }

    while ((de = readdir(busdir)) != NULL) {
        if (!is_usbdevname(de->d_name)) {
            LOG_DEBUG("badname : %s\n", de->d_name);
            continue;
        }

        snprintf(busname, sizeof(busname), "%s/%s", base, de->d_name);
        LOG_DEBUG("inotify add path: %s\n", busname);

        watch_fds[bus_cnt] = inotify_add_watch(inotify_fd, busname, IN_CREATE);
        if(watch_fds < 0) {
            LOG_DEBUG("failed to inotify_add_watch()\n");
            if (bus_cnt > 0)
                remove_watches(inotify_fd, bus_cnt, watch_fds);
            bus_cnt = -1;
            break;
        }
        bus_cnt++;
        if (bus_cnt >= USB_MAXBUS) {
            LOG_DEBUG("The number of usb bus is exceeded.\n");
            break;
        }
    }

    closedir(busdir);
    return bus_cnt;
}
#endif

void* usb_callback_thread(void* sleep_msec) {
    LOG_DEBUG("created usb callback thread\n");
#if HAVE_UDEV
    int mseconds = (int) sleep_msec;

    usb_register_callback(mseconds);
#else

#if SDB_USB_INOTIFY
    int inotify_fd = -1;
    int watch_fds[USB_MAXBUS] = {0,};
    int bus_cnt = 0;
    char inotify_buf[INOTIFY_BUF_SIZE] = {0,};

    inotify_fd = inotify_init();
    if(inotify_fd < 0) {
        LOG_DEBUG("failed to inotify_init()\n");
        goto poll_routine;
    }

    bus_cnt = inotify_add_watch_usb_bus(USB_DEV_BASE_PATH, inotify_fd, watch_fds);
    if(bus_cnt < 0) {
        LOG_DEBUG("failed to watch usb bus\n");
        sdb_close(inotify_fd);
        goto poll_routine;
    }

    find_usb_device(USB_DEV_BASE_PATH);

    while (1) {
        int length, i = 0;

        length = read(inotify_fd, inotify_buf, INOTIFY_BUF_SIZE);
        if (length < 0) {
            LOG_DEBUG("failed to read inotify event. error=%s\n", strerror(errno));
            break;
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) inotify_buf;
            char devname[32] = {0,};

            LOG_DEBUG("inotify event. mask=%x, name=%s\n", event->mask, event->name);

            /* XXX: Timing issues
             * Should wait until udev rule script is finished to add the permissions
             * in order to invoke the systemcall(open, ioctl) for usb device node.
             */
            sleep(1);
            find_usb_device(USB_DEV_BASE_PATH);

            i += INOTIFY_EVENT_SIZE + event->len;
        }
    }

    remove_watches(inotify_fd, bus_cnt, watch_fds);
    sdb_close(inotify_fd);

poll_routine:
#endif
    poll_usb_device();
#endif

    return NULL;
}

void sdb_usb_init(void) {
    sdb_thread_t tid;

    if (sdb_thread_create(&tid, usb_callback_thread, (void*) (250 * 1000))) {
        LOG_FATAL("cannot create input thread\n");
    }
}

void sdb_usb_cleanup() {
    close_usb_devices();
}

#define URB_USERCONTEXT_COOKIE      ((void *)0x1)

static int usb_urb_transfer(usb_handle *h, int ep, char *bytes, int size,
        int timeout, int rwtype) {
    int bytesdone = 0, requested;
    struct timeval tv, tv_ref, tv_now;
    struct usbdevfs_urb *p_urb;
    struct usbdevfs_urb *context;
    int ret, waiting;

    struct timeval tv_cur;
    /*
     * HACK: The use of urb.usercontext is a hack to get threaded applications
     * sort of working again. Threaded support is still not recommended, but
     * this should allow applications to work in the common cases. Basically,
     * if we get the completion for an URB we're not waiting for, then we update
     * the usercontext pointer to 1 for the other threads URB and it will see
     * the change after it wakes up from the the timeout. Ugly, but it works.
     */

    /*
     * Get actual time, and add the timeout value. The result is the absolute
     * time where we have to quit waiting for an message.
     */
    if (gettimeofday(&tv_cur, NULL) != 0) {
        LOG_DEBUG("failed to read clock\n");
        return -1;
    }
    tv_cur.tv_sec = tv_cur.tv_sec + timeout / 1000;
    tv_cur.tv_usec = tv_cur.tv_usec + (timeout % 1000) * 1000;

    if (tv_cur.tv_usec > 1000000) {
        tv_cur.tv_usec -= 1000000;
        tv_cur.tv_sec++;
    }

    do {
        LOG_DEBUG_URB("URB[%d]: do-while: entered\n", rwtype);
        fd_set writefds;

        requested = size - bytesdone;
        if (requested > MAX_READ_WRITE) {
            requested = MAX_READ_WRITE;
            LOG_DEBUG("requested bytes over than %d\n", MAX_READ_WRITE);
        }

        if ( rwtype == SDB_URB_TYPE_READ ) {
            memset(&(h->urb_in), 0, sizeof(h->urb_in));
            p_urb = &(h->urb_in);
            LOG_DEBUG_URB("URB[%d]: READ urb type: p_urb=%p\n", rwtype, p_urb);
        } else if ( rwtype == SDB_URB_TYPE_WRITE ) {
            memset(&(h->urb_out), 0, sizeof(h->urb_out));
            p_urb = &(h->urb_out);
            LOG_DEBUG_URB("URB[%d]: WRITE urb type: p_urb=%p\n", rwtype, p_urb);
        } else {
            LOG_ERROR("Unknown URB type : %d\n", rwtype);
            return -1;
        }

        p_urb->type = USBDEVFS_URB_TYPE_BULK;
        p_urb->endpoint = ep;
        p_urb->flags = 0;
        p_urb->buffer = bytes + bytesdone;
        p_urb->buffer_length = requested;
        p_urb->signr = 0;
        p_urb->actual_length = 0;
        p_urb->number_of_packets = 0; /* don't do isochronous yet */
        p_urb->usercontext = NULL;

        ret = ioctl(h->node_fd, USBDEVFS_SUBMITURB, p_urb);
        if (ret < 0) {
            LOG_DEBUG("failed to submit urb: %s\n", strerror(errno));
            return -1;
        }
        LOG_DEBUG_URB("URB[%d]: urb submit: p_urb=%p requested=%d, size=%d, bytesdone=%d\n", rwtype, p_urb, requested, size, bytesdone);

        FD_ZERO(&writefds);
        FD_SET(h->node_fd, &writefds);

        restart: waiting = 1;
        context = NULL;
        for (;;) {
            ret = ioctl(h->node_fd, USBDEVFS_REAPURBNDELAY, &context);
            int saved_errno = errno;
            LOG_DEBUG_URB("URB[%d]: urb reapndelay: ret=%d, saved_errno=%d, context=%p, waiting=%d, urb.usercontext=%p\n", rwtype, ret, saved_errno, context, waiting, p_urb->usercontext);
            if (!p_urb->usercontext && (ret == -1) && waiting) {
                // continue but,
                if (saved_errno == ENODEV) {
                    LOG_DEBUG("device may be unplugged: %s\n", strerror(saved_errno));
                    break;
                }
            } else {
                break;
            }

            tv.tv_sec = 0;
            tv.tv_usec = 1000; // 1 msec

            select(h->node_fd + 1, NULL, &writefds, NULL, &tv); //sub second wait

            if (timeout) {
                /* compare with actual time, as the select timeout is not that precise */
                gettimeofday(&tv_now, NULL);

                if ((tv_now.tv_sec > tv_cur.tv_sec)
                        || ((tv_now.tv_sec == tv_cur.tv_sec)
                                && (tv_now.tv_usec >= tv_ref.tv_usec))) {
                    waiting = 0;
                }
            }
        }

        LOG_DEBUG_URB("URB[%d]: leave reap loop: context=%p, p_urb=%p\n", rwtype, context, p_urb);
        if (context && context != p_urb) {
            context->usercontext = URB_USERCONTEXT_COOKIE;
            /* We need to restart since we got a successful URB, but not ours */
            LOG_DEBUG_URB("URB[%d]: usercontext cookie: not ours\n", rwtype);
            goto restart;
        }

        /*
         * If there was an error, that wasn't EAGAIN (no completion), then
         * something happened during the reaping and we should return that
         * error now
         */
        if (ret < 0 && !p_urb->usercontext && errno != EAGAIN)
            LOG_DEBUG("error reaping URB: %s\n", strerror(errno));

        bytesdone += p_urb->actual_length;

        LOG_DEBUG_URB("URB[%d]: do-while: check condition: ret=%d, urb.usercontext=%p, bytesdone=%d, size=%d, urb.actual_length=%d, requested=%d\n", rwtype, ret, p_urb->usercontext, bytesdone, size, p_urb->actual_length, requested);
    } while ((ret == 0 || p_urb->usercontext) && bytesdone < size
            && p_urb->actual_length == requested);
    LOG_DEBUG_URB("URB[%d]: do-while: leaved\n", rwtype);

    /* If the URB didn't complete in success or error, then let's unlink it */
    if (ret < 0 && !p_urb->usercontext) {
        LOG_DEBUG_URB("URB[%d]: urb error case: entered\n", rwtype);
        int rc;
        if (!waiting)
            rc = -ETIMEDOUT;
        else
            rc = p_urb->status;

        ret = ioctl(h->node_fd, USBDEVFS_DISCARDURB, p_urb);
        if (ret < 0 && errno != EINVAL)
            LOG_DEBUG("error discarding URB: %s\n", strerror(errno));

        LOG_DEBUG_URB("URB[%d]: urb discard: ret=%d, errno=%d\n", rwtype, ret, errno);

        /*
         * When the URB is unlinked, it gets moved to the completed list and
         * then we need to reap it or else the next time we call this function,
         * we'll get the previous completion and exit early
         */
        ret = ioctl(h->node_fd, USBDEVFS_REAPURB, &context);
        if (ret < 0 && errno != EINVAL)
            LOG_DEBUG("error reaping URB: %s\n", strerror(errno));

        LOG_DEBUG_URB("URB[%d]: urb reap: ret=%d, errno=%d\n", rwtype, ret, errno);

        return rc;
    }

    LOG_DEBUG_URB("URB[%d]: urb transfer done: bytesdone=%d\n", rwtype, bytesdone);
    return bytesdone;
}

int sdb_usb_write(usb_handle *h, const void *_data, int len) {
    char *data = (char*) _data;
    int n = 0;

    LOG_DEBUG("+sdb_usb_write\n");

    while (len > 0) {
        int xfer = (len > MAX_READ_WRITE) ? MAX_READ_WRITE : len;

        n = usb_urb_transfer(h, h->end_point[1], data, xfer, URB_TRANSFER_TIMEOUT, SDB_URB_TYPE_WRITE);
        if (n != xfer) {
            LOG_DEBUG("fail to usb write: n = %d, errno = %d (%s)\n", n, errno, strerror(errno));
            return -1;
        }

        len -= xfer;
        data += xfer;
    }

    LOG_DEBUG("-usb_write\n");

    return 0;
}

int sdb_usb_read(usb_handle *h, void *_data, int len) {
    char *data = (char*) _data;
    int n;

    LOG_DEBUG("+sdb_usb_read\n");

    while (len > 0) {
        int xfer = (len > MAX_READ_WRITE) ? MAX_READ_WRITE : len;

        n = usb_urb_transfer(h, h->end_point[0], data, xfer, URB_TRANSFER_TIMEOUT, SDB_URB_TYPE_READ);
        if (n != xfer) {
            if ((errno == ETIMEDOUT)) {
                LOG_DEBUG("usb bulk read timeout\n");
                if (n > 0) {
                    data += n;
                    len -= n;
                }
                continue;
            }
            LOG_DEBUG("fail to usb read: n = %d, errno = %d (%s)\n", n, errno, strerror(errno));
            return -1;
        }

        len -= xfer;
        data += xfer;
    }

    LOG_DEBUG("-sdb_usb_read\n");

    return 0;
}

void sdb_usb_kick(usb_handle *h) {
    LOG_DEBUG("+kicking\n");
    LOG_DEBUG("-kicking\n");
}

int sdb_usb_close(usb_handle *h) {
    LOG_DEBUG("+usb close\n");

    if (h != NULL) {
        sdb_mutex_lock(&usb_lock, "usb close locked");
        remove_node(&usb_list, h->node, no_free);
        sdb_close(h->node_fd);
        free(h);
        h = NULL;
        sdb_mutex_unlock(&usb_lock, "usb close unlocked");
    }
    LOG_DEBUG("-usb close\n");
    return 0;
}

