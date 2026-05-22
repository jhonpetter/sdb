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
 *
 * documents from https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/USBBook/USBOverview/USBOverview.html
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include "fdevent.h"
#include "strutils.h"
#include "memutils.h"
#include "sdb_usb.h"
#include "device_vendors.h"
#include "log.h"
#include "utils.h"
#include "linkedlist.h"
#include "transport.h"

#define kUSBLanguageEnglish     0x409

static IONotificationPortRef gNotifyPort;
static io_iterator_t* gAddedIter;
static CFRunLoopRef gRunLoop;

static pthread_mutex_t usb_init_lock;
static pthread_cond_t usb_init_cond;

struct usb_handle {
    UInt8 end_point[2]; // 0:in, 1:out
    IOUSBInterfaceInterface **interface;
    io_object_t usbNotification;
    unsigned int zero_mask;
};

static void usb_unplugged(usb_handle *handle) {
    LOG_INFO("clean interface resources\n");
    if (!handle)
        return;

    if (handle->interface) {
        (*handle->interface)->USBInterfaceClose(handle->interface);
        (*handle->interface)->Release(handle->interface);
        handle->interface = 0;
    }
}

void DeviceRemoveNotification(void * refCon, io_service_t service, natural_t messageType,
        void * messageArgument) {

    kern_return_t kr;
    usb_handle *handle = (usb_handle *) refCon;

    if (messageType == kIOMessageServiceIsTerminated) {
        LOG_DEBUG("Device 0x%08x removed.\n", service);

        kr = IOObjectRelease(handle->usbNotification);
        sdb_usb_kick(handle);
    }

}

/**
 * Authors: Vipul Gupta, Pete St. Pierre
 **/
static void UsbCharactersToHostCharacters(UniChar *p, UInt16 len) {
    for (; len > 0; --len, ++p)
        *p = USBToHostWord(*p);
}

kern_return_t getUSBSerial(IOUSBDeviceInterface182 **dev, UInt8 string_id, char *spotSerial) {
    UInt8 buffer[256];
    UInt16 result_length;
    CFStringRef result;
    kern_return_t kr = -1;
    IOUSBDevRequest request;

    memset(buffer, 0, sizeof(buffer));
    if (string_id != 0) {
        result_length = sizeof(buffer);
        request.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBStandard, kUSBDevice);
        request.bRequest = kUSBRqGetDescriptor;
        request.wValue = (kUSBStringDesc << 8) | string_id;
        request.wIndex = kUSBLanguageEnglish;
        request.wLength = result_length;
        request.pData = buffer;
        kr = (*dev)->DeviceRequest(dev, &request);

        if ((kIOReturnSuccess == kr) && (request.wLength > 0)
                && (request.wLength <= sizeof(buffer))) {
            result_length = buffer[0];
            if ((0 < result_length) && (result_length <= sizeof(buffer))) {
                /*
                 * Convert USB string (always little-endian) to host-endian but
                 * leave the descriptor type byte and the length alone.
                 */
                UsbCharactersToHostCharacters(((UniChar *) buffer) + 1, ((result_length - 2) >> 1));

                /* Recreate a string from the buffer of unicode characters */
                result = CFStringCreateWithCharacters(kCFAllocatorDefault, ((UniChar *) buffer) + 1,
                        ((result_length - 2) >> 1));

                /* Copy the character contents to a local C string */
                CFStringGetCString(result, spotSerial, MAX_SERIAL_NAME, kCFStringEncodingASCII);
            }
        }
    }

    return kr;
}

void register_usb(IOUSBDeviceInterface182 **dev, usb_handle *handle, platform_type platform) {
    IOReturn ior;
    kern_return_t kr;
    UInt8 serialIndex;
    char serial[256] = {0,};

    // get serial index
    ior = (*dev)->USBGetSerialNumberStringIndex(dev, &serialIndex);
    if (kIOReturnSuccess != ior) {
        LOG_ERROR("couldn't get usb serial index\n");
    }

    // get serial
    kr = getUSBSerial(dev, serialIndex, serial);
    if (kIOReturnSuccess != kr) {
        LOG_ERROR("couldn't get usb serial\n");
    }

    register_usb_transport(handle, serial, platform);

    // Register for an interest notification of this device being removed.
    // Pass the reference to our private data as the refCon for the notification.
    kr = IOServiceAddInterestNotification(gNotifyPort, // notifyPort
            handle->interface, // service
            kIOGeneralInterest, // interestType
            DeviceRemoveNotification, // callback
            handle, // refCon
            &(handle->usbNotification) // notification
            );

    if (kIOReturnSuccess != kr) {
        LOG_ERROR("IOServiceAddInterestNotification returned 0x%08x\n", kr);
    }
}

UInt8 find_sdb_interface_by_looping_configuration(IOUSBDeviceInterface182 **dev, usb_handle* handle) {

    IOReturn ior;
    kern_return_t kr;
    UInt8 totalConfigNum = 0;
    UInt8 configNum;
    platform_type platform;

    // find SDB interface in current configuration
    ior = FindSDBInterface(dev, handle, &platform);
    if (!ior) {
        LOG_DEBUG("found tizen device and register usb transport.........\n");
        register_usb(dev, handle, platform);
        return 0;
    }

    // get total number of configurations
    ior = (*dev)->GetNumberOfConfigurations(dev, &totalConfigNum);
    LOG_DEBUG("total number of configurations: %d\n", totalConfigNum);
    if (ior) {
        LOG_ERROR("Can not get total number of configuration\n", (int )totalConfigNum);
        return -1;
    }
    if (totalConfigNum  == 0 || totalConfigNum  == 1) {
        LOG_DEBUG("total number of configuration is %d, no need to loop configurations\n", totalConfigNum);
        return -1;
    }

    // get current configuration
    ior = (*dev)->GetConfiguration(dev, &configNum);
    if (ior) {
        LOG_ERROR("failed to get current configuration\n");
        return -1;
    }
    LOG_DEBUG("get current configuration: %d\n", configNum);

    // set other configurations
    // Open the device before configuring it
    ior = (*dev)->USBDeviceOpen(dev);
    if (ior) {
        LOG_ERROR("Unable to open device: %08x\n", ior);
        return -1;
    } else {
        UInt8 sdb_configuration;
        for (sdb_configuration = 1; sdb_configuration <= totalConfigNum; sdb_configuration++)
        {
            if (sdb_configuration == configNum || (configNum == 0 && sdb_configuration == 1))
                continue;

            // Set configuration
            ior = (*dev)->SetConfiguration(dev, sdb_configuration);
            if (ior) {
                LOG_ERROR("failed to set configuration to %d (err = %08x)\n", sdb_configuration, ior);
                continue;
            } else {
                LOG_DEBUG("set configuration to %d\n", sdb_configuration);
                // find SDB interface in configuration
                if (FindSDBInterface(dev, handle, &platform) != 0)
                    continue;
                else {
                    LOG_DEBUG("found SDB interface in configuration: %d\n", sdb_configuration);
                    register_usb(dev, handle, platform);
                    kr = (*dev)->USBDeviceClose(dev);
                    return 0;
                }
            }
        }
    }
    kr = (*dev)->USBDeviceClose(dev);
    return -1;
}

IOReturn FindSDBInterface(IOUSBDeviceInterface **device,
        usb_handle* handle, platform_type* platform_type_ptr) {
    IOReturn kr = -1;
    IOUSBFindInterfaceRequest request;
    io_iterator_t iterator;
    io_service_t usbInterface;
    IOCFPlugInInterface **plugInInterface = NULL;
    IOUSBInterfaceInterface **interface = NULL;
    HRESULT result;
    SInt32 score;
    UInt8 interfaceClass;
    UInt8 interfaceSubClass;
    UInt8 intfProtocol;
    UInt8 interfaceNumEndpoints;
    UInt8 interfaceNumConf;
    int pipeRef;

#ifndef USE_ASYNC_IO
    UInt32 numBytesRead;
    UInt32 i;
#else
    CFRunLoopSourceRef runLoopSource;
#endif

    //Placing the constant kIOUSBFindInterfaceDontCare into the following
    //fields of the IOUSBFindInterfaceRequest structure will allow you
    //to find all the interfaces
    request.bInterfaceClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
    request.bAlternateSetting = kIOUSBFindInterfaceDontCare;

    //Get an iterator for the interfaces on the device
    kr = (*device)->CreateInterfaceIterator(device, &request, &iterator);

    //Enumerate all the device interfaces in device
    while (usbInterface = IOIteratorNext(iterator)) {
        //Create an intermediate plug-in
        kr = IOCreatePlugInInterfaceForService(usbInterface,
                kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID,
                &plugInInterface, &score);
        //Release the usbInterface object after getting the plug-in
        kr = IOObjectRelease(usbInterface);
        if ((kr != kIOReturnSuccess) || !plugInInterface) {
            LOG_DEBUG("Unable to create a plug-in (%08x)\n", kr);
            continue;
        }

        //Now create the device interface for the interface
        result = (*plugInInterface)->QueryInterface(plugInInterface,
                CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID),
                (LPVOID *) &interface);
        //No longer need the intermediate plug-in
        (*plugInInterface)->Release(plugInInterface);

        if (result || !interface) {
            LOG_DEBUG("Could not create a device interface for the interface(%08x)\n", result);
            continue;
        }

        //Get interface class and subclass and protocol
        kr = (*interface)->GetInterfaceClass(interface, &interfaceClass);
        kr = (*interface)->GetInterfaceSubClass(interface, &interfaceSubClass);
        kr = (*interface)->GetInterfaceProtocol(interface, &intfProtocol);

        LOG_DEBUG("Interface class %d, subclass %d protocol %d\n",
                interfaceClass, interfaceSubClass, intfProtocol);

        //Check if interface is sdb interface
        platform_type platform_type_temp = get_platform_type(VENDOR_ID_SAMSUNG, interfaceClass, interfaceSubClass, intfProtocol);
        if (platform_type_temp == PLATFORM_UNKNOWN) {
            LOG_DEBUG("it is not sdb interface\n");
            (*interface)->Release(interface);
            continue;
        } else {
            *platform_type_ptr = platform_type_temp;
        }

        // get number of end points
        kr = (*interface)->GetNumEndpoints(interface, &interfaceNumEndpoints);
        if (kIOReturnSuccess != kr) {
            LOG_DEBUG("unable to get number of endpoints (%08x)\n", kr);
            (*interface)->Release(interface);
            continue;
        }

        // open the interface. This will cause the pipes to be instantiated that are
        // associated with the endpoints defined in the interface descriptor.
        kr = (*interface)->USBInterfaceOpen(interface);
        if (kIOReturnSuccess != kr) {
            LOG_DEBUG("unable to open interface (%08x)\n", kr);
            (*interface)->Release(interface);
            continue;
        }

        for (pipeRef = 0; pipeRef <= interfaceNumEndpoints; pipeRef++) {
            UInt8 direction;
            UInt8 number;
            UInt8 transferType;
            UInt16 maxPacketSize;
            UInt8 interval;
            char *message;

            kr = (*interface)->GetPipeProperties(interface, pipeRef, &direction,
                    &number, &transferType, &maxPacketSize, &interval);
            if (kIOReturnSuccess != kr)
                LOG_DEBUG("unable to get properties of pipe %d (%08x)\n", pipeRef, kr);
            else {
                LOG_DEBUG("++ pipeRef:%d: ++\n ", pipeRef);

                switch (transferType) {
                case kUSBControl:
                    message = "control";
                    break;
                case kUSBIsoc:
                    message = "isoc";
                    break;
                case kUSBBulk:
                    message = "bulk";
                    break;
                case kUSBInterrupt:
                    message = "interrupt";
                    break;
                case kUSBAnyType:
                    message = "any";
                    break;
                default:
                    message = "???";
                }
                LOG_DEBUG("transfer type:%s, maxPacketSize:%d\n", message, maxPacketSize);
                if (kUSBBulk != transferType) {
                    continue;
                }
                handle->zero_mask = maxPacketSize - 1;

                switch (direction) {
                case kUSBOut:
                    message = "out";
                    handle->end_point[1] = pipeRef;
                    break;
                case kUSBIn:
                    message = "in";
                    handle->end_point[0] = pipeRef;
                    break;
                case kUSBNone:
                    message = "none";
                    break;
                case kUSBAnyDirn:
                    message = "any";
                    break;
                default:
                    message = "???";
                }
                LOG_DEBUG("direction:%0x(%s)\n", pipeRef, message);
            }
        }
        handle->interface = interface;
        return 0;
    }
    return -1;
}

void DeviceAdded(void *refCon, io_iterator_t iterator) {
    kern_return_t kr;
    IOReturn ior;
    io_service_t usbDevice;
    IOCFPlugInInterface **plugInInterface = NULL;
    IOUSBDeviceInterface182 **dev = NULL;
    HRESULT result;
    SInt32 score;

    LOG_DEBUG("iterate devices start\n");
    while (usbDevice = IOIteratorNext(iterator)) {
        LOG_DEBUG("new device in !\n");
        //Create an intermediate plug-in
        kr = IOCreatePlugInInterfaceForService(usbDevice,
                kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID,
                &plugInInterface, &score);
        //Don't need the device object after intermediate plug-in is created
        kr = IOObjectRelease(usbDevice);
        if ((kIOReturnSuccess != kr) || !plugInInterface) {
            LOG_DEBUG("Unable to create a plug-in (%08x)\n", kr);
            continue;
        }

        //Create the device interface
        result = (*plugInInterface)->QueryInterface(plugInInterface,
                CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID *) &dev);
        //Don't need the intermediate plug-in after device interface is created
        (*plugInInterface)->Release(plugInInterface);
        if (result || !dev) {
            LOG_DEBUG("Could not create a device interface (%08x)\n", (int ) result);
            continue;
        }

        usb_handle* handle = calloc(1, sizeof(usb_handle));
        if (handle == NULL) {
            LOG_FATAL("could't alloc mememroy\n");
        }

        // find SDB interface
        if (find_sdb_interface_by_looping_configuration(dev, handle) != 0) {
            SAFE_FREE(handle);
        }
        (*dev)->Release(dev);
    }
    LOG_DEBUG("iterate devices end\n");
    LOG_DEBUG("signal to wake up main thread\n");
    sdb_mutex_lock(&usb_init_lock, "++usb locking++");
    sdb_cond_signal(&usb_init_cond);
    sdb_mutex_unlock(&usb_init_lock, "--usb unlocking--");
}

static int cleanup_flag = 0;
static void sig_handler(int sigraised) {
    int i = 0;

    LOG_DEBUG("Interrupted!\n");

    if (cleanup_flag == 1) {
        return;
    }

    // Clean up
    for (i = 0; i < vendor_total_cnt; i++) {
        IOObjectRelease(gAddedIter[i]);
    }
    gAddedIter = NULL;

    IONotificationPortDestroy(gNotifyPort);
    gRunLoop = 0;

    if (gAddedIter != NULL) {
        s_free(gAddedIter);
        gAddedIter = NULL;
    }

    LOG_DEBUG("RunLoopThread done\n");
    if (gRunLoop) {
        CFRunLoopStop(gRunLoop);
    }
    cleanup_flag = 1;
}

void do_lsusb(void) {
    mach_port_t masterPort;
    CFMutableDictionaryRef matchingDict;
    CFRunLoopSourceRef runLoopSource;
    CFNumberRef numberRef;
    kern_return_t kr;
    SInt32 usbVendor, subClass, protocol;
    sig_t oldHandler;
    int i = 0;

    // Set up a signal handler so we can clean up when we're interrupted from the command line
    // Otherwise we stay in our run loop forever.
    //
    oldHandler = signal(SIGINT, sig_handler);
    if (oldHandler == SIG_ERR) {
        LOG_DEBUG("Could not establish new signal handler\n");
    }

    // first create a master_port for my task
    //
    kr = IOMasterPort(MACH_PORT_NULL, &masterPort);
    if (kr || !masterPort) {
        LOG_DEBUG("ERR: Couldn't create a master IOKit Port(%08x)\n", kr);
        return;
    }

    // Create a notification port and add its run loop event source to our run loop
    // This is how async notifications get set up.
    //
    gNotifyPort = IONotificationPortCreate(masterPort);
    runLoopSource = IONotificationPortGetRunLoopSource(gNotifyPort);

    gRunLoop = CFRunLoopGetCurrent();
    CFRunLoopAddSource(gRunLoop, runLoopSource, kCFRunLoopDefaultMode);

    // Set up the matching criteria for the devices we're interested in.  The matching criteria needs to follow
    // the same rules as kernel drivers:  mainly it needs to follow the USB Common Class Specification, pp. 6-7.
    // See also http://developer.apple.com/qa/qa2001/qa1076.html
    // One exception is that you can use the matching dictionary "as is", i.e. without adding any matching criteria
    // to it and it will match every IOUSBDevice in the system.  IOServiceAddMatchingNotification will consume this
    // dictionary reference, so there is no need to release it later on.
    //
    matchingDict = IOServiceMatching(kIOUSBDeviceClassName); // Interested in instances of device class

    if (!matchingDict) {
        LOG_DEBUG("Can't create a USB matching dictionary\n");
        mach_port_deallocate(mach_task_self(), masterPort);
        return;
    }

    LOG_DEBUG("Looking for devices matching vendor ID=%0x(%0x, %0x)\n",
            usbVendor, subClass, protocol);

    // We are interested in all USB Devices (as opposed to USB interfaces).  The Common Class Specification
    // tells us that we need to specify the idVendor, idProduct, and bcdDevice fields, or, if we're not interested
    // in particular bcdDevices, just the idVendor and idProduct.  Note that if we were trying to match an IOUSBInterface,
    // we would need to set more values in the matching dictionary (e.g. idVendor, idProduct, bInterfaceNumber and
    // bConfigurationValue.
    //

    // Create a CFNumber for the idVendor, interface subclass and protocol and set the value in the dictionary
    //
    numberRef = 0;

    // Now set up a notification to be called when a device is first matched by I/O Kit.
    // Note that this will not catch any devices that were already plugged in so we take
    // care of those later.
    //
    kr = IOServiceAddMatchingNotification(gNotifyPort, // notifyPort
            kIOFirstMatchNotification, // notificationType
            matchingDict, // matching
            DeviceAdded, // callback
            NULL, // refCon
            &gAddedIter[i] // notification
            );
    if(kr) {
        LOG_ERROR("ERR: Couldn't add matching notification(%08x)\n", kr);
    }

    // Iterate once to get already-present devices and arm the notification
    //
    DeviceAdded(NULL, gAddedIter[i]);

    // Now done with the master_port
    mach_port_deallocate(mach_task_self(), masterPort);
    masterPort = 0;

    // Start the run loop. Now we'll receive notifications.
    //
    LOG_DEBUG("Starting run loop.\n");
    CFRunLoopRun();

    // We should never get here
    //
    LOG_DEBUG("Unexpectedly back from CFRunLoopRun()!\n");
}

void* usb_poll_thread(void* sleep_msec) {
    LOG_DEBUG("created usb detecting thread\n");
    do_lsusb();
    return NULL;
}

void sdb_usb_init() {
    sdb_thread_t tid;

    init_device_vendors();
    gAddedIter = (io_iterator_t*) s_malloc(vendor_total_cnt * sizeof(io_iterator_t));
    if (gAddedIter == NULL) {
        LOG_FATAL("Cound not alloc memory\n");
        return;
    }

    sdb_mutex_init(&usb_init_lock, NULL);
    sdb_cond_init(&usb_init_cond, NULL);

    if (sdb_thread_create(&tid, usb_poll_thread, NULL)) {
        LOG_FATAL("cannot create usb poll thread\n");
    }
    sdb_mutex_lock(&usb_init_lock, "++usb locking++");

    LOG_DEBUG("waiting until to finish to initilize....\n");
    // wait til finish to initialize some setting for usb detection
    sdb_cond_wait(&usb_init_cond, &usb_init_lock);

    LOG_DEBUG("woke up done....\n");
    sdb_mutex_unlock(&usb_init_lock, "--usb unlocking--");
    sdb_mutex_destroy(&usb_init_lock);
    sdb_cond_destroy(&usb_init_cond);
}

void sdb_usb_cleanup() {
    // called when server stop or interrupted
    close_usb_devices();
    sig_handler(0);
}

int sdb_usb_write(usb_handle *h, const void *data, int len) {
    IOReturn kr;

    kr = (*h->interface)->WritePipe(h->interface, h->end_point[1], (void *) data, len);
    if (kr == kIOReturnSuccess) {
        if (h->zero_mask && !(h->zero_mask & len)) {
            (*h->interface)->WritePipe(h->interface, h->end_point[1], (void *) data, 0);
        }
        return 0;
    }

    LOG_DEBUG("Unable to perform bulk write (%08x)\n", kr);
    return -1;
}

int sdb_usb_read(usb_handle *h, void *data, int len) {
    IOReturn kr;
    UInt32 size = len;

    kr = (*h->interface)->ReadPipe(h->interface, h->end_point[0], data, &size);

    if (kIOUSBPipeStalled == kr) {
        LOG_DEBUG("Pipe stalled, clearing stall.\n");
        (*h->interface)->ClearPipeStall(h->interface, h->end_point[0]);
        kr = (*h->interface)->ReadPipe(h->interface, h->end_point[0], data, &size);
    }

    if (kIOReturnSuccess == kr) {
        return 0;
    }

    LOG_DEBUG("Unable to perform bulk read (%08x)\n", kr);
    return -1;
}

int sdb_usb_close(usb_handle *h) {
    return 0;
}

void sdb_usb_kick(usb_handle *h) {
    usb_unplugged(h);
}

