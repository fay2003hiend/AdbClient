#ifndef ADBDEVICENODE_H
#define ADBDEVICENODE_H

#include <QString>

class AdbDeviceJobThread;

class AdbDeviceNode
{
public:
    AdbDeviceNode();
    AdbDeviceJobThread *jobThread;

    int node_index;
    QString adb_serial;

    enum {
        CS_UNKNOWN = 0,
        CS_DISCONNECTED,
        CS_BOOTLOADER,
        CS_DEVICE,
        CS_RECOVERY,
        CS_SIDELOAD,
        CS_OFFLINE,
        CS_UNAUTHORIZED
    };
    int connect_stat;
    QString connect_statname;
    static int getStateFromName(const QString& name);

    // implement your self
    static AdbDeviceNode* newDeviceNode(const QString& serial, int index);
    static void delDeviceNode(AdbDeviceNode* node);
};

#endif // ADBDEVICENODE_H
