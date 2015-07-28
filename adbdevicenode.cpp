#include "adbdevicenode.h"

AdbDeviceNode::AdbDeviceNode()
{
    jobThread = NULL;
    node_index = -1;
    connect_statname = "unknown";
    connect_stat = CS_UNKNOWN;
}

int AdbDeviceNode::getStateFromName(const QString& name) {
    if(name == "bootloader") {
        return CS_BOOTLOADER;
    } else if(name == "device") {
        return CS_DEVICE;
    } else if(name == "recovery") {
        return CS_RECOVERY;
    } else if(name == "sideload") {
        return CS_SIDELOAD;
    } else if(name == "offline") {
        return CS_OFFLINE;
    } else if(name == "unauthorized") {
        return CS_UNAUTHORIZED;
    }
    return CS_UNKNOWN;
}
