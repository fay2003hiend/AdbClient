#ifndef ADBDEVICEJOBTHREAD_H
#define ADBDEVICEJOBTHREAD_H

#include <QThread>
class AdbDeviceNode;
class AdbDeviceJobThread : public QThread
{
    Q_OBJECT
public:
    AdbDeviceNode *node;
    bool needsQuit;

    AdbDeviceJobThread(AdbDeviceNode *node, QObject *parent = 0);
    ~AdbDeviceJobThread();
    void run();

    inline void stop() {
        needsQuit = true;
    }

    virtual void core_run() = 0;
signals:
    void sigDeviceRefresh(AdbDeviceNode *node);
    void sigDeviceStat(AdbDeviceNode *node, const QString& status);
    void sigDeviceProgress(AdbDeviceNode *node, int progress, int max);
    void sigDeviceLog(AdbDeviceNode *node, const QString& log);
};

#endif // ADBDEVICEJOBTHREAD_H
