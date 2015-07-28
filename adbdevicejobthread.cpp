#include "adbdevicejobthread.h"
#include "adbdevicenode.h"
#include "adbclient.h"
#include "zlog.h"

AdbDeviceJobThread::AdbDeviceJobThread(AdbDeviceNode *node, QObject *parent)
    : QThread(parent)
{
    this->node = node;
    needsQuit = false;
    node->jobThread = this;
    connect(this, SIGNAL(finished()), SLOT(deleteLater()));
}

AdbDeviceJobThread::~AdbDeviceJobThread() {
    node->jobThread = NULL;
}

void AdbDeviceJobThread::run() {
    bool ret = false;
    AdbClient adb(node->adb_serial);

    // wait for boot
    while(!needsQuit && node->connect_stat == AdbDeviceNode::CS_DEVICE) {
        if(adb.adb_cmd("shell:ps").contains("com.android")) {
            ret = true;
            break;
        }
        emit sigDeviceStat(node, "wait for boot...");
        QThread::msleep(5000);
    }
    if(!ret) {
        return;
    }

    DBG("jobThread starts...\n");
    core_run();
    DBG("jobThread ends.\n");
}
