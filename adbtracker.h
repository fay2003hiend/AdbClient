#ifndef ADBTRACKER_H
#define ADBTRACKER_H

#include <QThread>
#include <QMutex>
#include <QList>
class AdbDeviceNode;
class AdbTracker;
class AdbNurse : public QThread {
    Q_OBJECT
    bool needsQuit;
    int adbPid;
    AdbTracker *parent;
    void adb_hanged();
public:
    AdbNurse(AdbTracker *parent, int pid);

    inline void stop() {
        needsQuit = true;
    }

    void run();
};

class AdbTracker : public QThread {
    Q_OBJECT
    QString adb_exe;
    bool needsQuit;

    QList<AdbDeviceNode *> deviceList;
    QList<AdbDeviceNode *> delList;
    QMutex deviceList_mutex;
    void refreshDeviceList(const QByteArray& data);
    void core_run();
public:
    bool adbHanged;

    AdbTracker(const QString& adb_exe, QObject *parent);
    ~AdbTracker();
    static int getAdbPid(QString& processName);

    void run();

    inline void stop() {
        needsQuit = true;
    }

    void cleanUp();
    void freeMem();
    int getActiveCount();
    QList<AdbDeviceNode *> getDeviceList();

signals:
    void sigDone(QObject *p);
    void sigAdbError(const QString& hint, int pid);
    void sigDevListChanged();
};

#endif // ADBTRACKER_H
