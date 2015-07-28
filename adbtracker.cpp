#include "adbtracker.h"
#include <QTcpSocket>
#include "adbdevicenode.h"
#include "adbprocess.h"
#include "zlog.h"

#define ADB_DEFAULT_PORT 5037

#ifdef Q_OS_WIN
#include <WinSock2.h>
#include <IPHlpApi.h>
#include <TlHelp32.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/types.h>
#include <signal.h>
#include <QFile>
#endif

static bool writex(QTcpSocket *socket, const char *str) {
    int n;
    int len = strlen(str);
    char tmp[8];
    sprintf(tmp, "%04X", len);

    if((n = socket->write(tmp, 4)) != 4) {
        return false;
    }

    if((n = socket->write(str, len)) != len) {
        return false;
    }
    socket->waitForBytesWritten();

    return true;
}

static QByteArray readx(QTcpSocket *socket, int len) {
    socket->waitForReadyRead(200);
    return socket->read(len);
}

AdbNurse::AdbNurse(AdbTracker *parent, int pid)
    : QThread(0){
    needsQuit = false;
    this->parent = parent;
    this->adbPid = pid;
}

void AdbNurse::adb_hanged() {
    DBG("### adbHang ###\n");
    parent->adbHanged = true;
    if(adbPid != -1) {
        DBG("try kill the adb pid %d\n", adbPid);
#ifdef Q_OS_WIN
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, adbPid);
        if(h != NULL) {
            TerminateProcess(h, 0);
        }
#else
        kill(adbPid, SIGKILL);
#endif
    }
}

void AdbNurse::run() {
    QTcpSocket socket;
    QByteArray tmp;

    while(!needsQuit) {
        socket.connectToHost("127.0.0.1", ADB_DEFAULT_PORT);
        if(!socket.waitForConnected(500)) {
            socket.abort();
            DBG("connect adb host fail\n");
            adb_hanged();
            break;
        }

        if(!writex(&socket, "host:version") || readx(&socket, 4) != "OKAY") {
            DBG("read host:version resp fail!\n");
            adb_hanged();
            break;
        }

        socket.waitForReadyRead(200);
        if((tmp = socket.read(4)).size() != 4) {
            DBG("read version len fail!\n");
            adb_hanged();
            break;
        }

        tmp = socket.read(tmp.toInt());
        socket.disconnectFromHost();

        parent->adbHanged = false;

        QThread::msleep(500);
    }
    socket.abort();
    DBG("adbNurse quit\n");
}

AdbTracker::AdbTracker(const QString& adb_exe, QObject *parent) :
    QThread(parent)
{
    DBG("AdbTracker +%p\n", this);
    this->adb_exe = adb_exe;
    needsQuit = false;
    adbHanged = false;
}

AdbTracker::~AdbTracker() {
    DBG("AdbTracker ~%p\n", this);
}

void AdbTracker::refreshDeviceList(const QByteArray &data) {
    QStringList lines = QString::fromUtf8(data.data(), data.size()).split('\n');
    QList<AdbDeviceNode *> lostDevices;

    deviceList_mutex.lock();
    lostDevices.append(deviceList);

    foreach(const QString& line, lines) {
        int n = line.indexOf('\t');
        if(n == -1) {
            continue;
        }
        QString serial = line.left(n);
        QString cstate = line.mid(n+1);

        bool found = false;
        foreach(AdbDeviceNode *node, lostDevices) {
            if(node->adb_serial == serial) {
                found = true;
                lostDevices.removeOne(node); // remove from lost list
                node->connect_statname = cstate;
                node->connect_stat = AdbDeviceNode::getStateFromName(cstate); // update new state
                DBG("new state: '%s'->'%s'\n", serial.toLocal8Bit().data(),
                    cstate.toLocal8Bit().data());
                break;
            }
        }

        if(!found && !serial.startsWith("usb_")
                && !serial.endsWith("_mdb")) {
            DBG("new device: '%s'->'%s'\n", serial.toLocal8Bit().data(),
                cstate.toLocal8Bit().data());
            int index = deviceList.size() + 1;
            AdbDeviceNode *node = AdbDeviceNode::newDeviceNode(serial, index);
            node->connect_statname = cstate;
            node->connect_stat = AdbDeviceNode::getStateFromName(cstate);
            deviceList.append(node);
        }
    }

    foreach(AdbDeviceNode *node, lostDevices) {
        node->connect_statname = "disconnected";
        node->connect_stat = AdbDeviceNode::CS_DISCONNECTED;
        DBG("lost device: '%s'\n", node->adb_serial.toLocal8Bit().data());
    }

    deviceList_mutex.unlock();
}

#ifndef Q_OS_WIN
static QByteArray getNetstatArg(const QByteArray& line, int pos) {
    if(pos == -1) {
        return QByteArray();
    }
    int r = line.indexOf(' ', pos);
    return line.mid(pos, r == -1 ? -1 : r-pos);
}
#endif

int AdbTracker::getAdbPid(QString &processName) {
    int ret = -1;
#ifdef Q_OS_WIN
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    unsigned long dwSize = 0;
    unsigned long dwRetVal = 0;

    int i;

    if((dwRetVal = GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)!=NO_ERROR)) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID) malloc(dwSize);
        if(pTcpTable == NULL) {
            DBG("Error malloc!\n");
            return -1;
        }
    }

    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)) == NO_ERROR) {
        for (i = 0; i < (int) pTcpTable->dwNumEntries; i++) {
            if(ntohs(pTcpTable->table[i].dwLocalPort)!=ADB_DEFAULT_PORT) {
                continue;
            }

            if(pTcpTable->table[i].dwState != MIB_TCP_STATE_LISTEN) {
                continue;
            }

            ret = pTcpTable->table[i].dwOwningPid;
            break;
        }
    } else {
        DBG("\tGetExtendedTcpTable failed with %d\n", dwRetVal);
    }

    if(pTcpTable!=NULL) {
        free(pTcpTable);
        pTcpTable=NULL;
    }

    if(ret != -1) {
        LPMODULEENTRY32 module_entry = (LPMODULEENTRY32 ) malloc(sizeof(MODULEENTRY32));
        PPROCESSENTRY32 process_entry = (PPROCESSENTRY32 ) malloc(sizeof(PROCESSENTRY32));
        bool found = false;
        process_entry->dwSize = sizeof(PROCESSENTRY32);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ret);
        if(snap) {
            if(Module32First(snap, module_entry)) {
                do {
                    if(module_entry->th32ProcessID == ret) {
                        DBG("got module, name=%s\n", module_entry->szExePath);
                        processName = QString::fromLocal8Bit(module_entry->szExePath);
                        found = true;
                        break;
                    }
                } while(Module32Next(snap, module_entry));
            }
            CloseHandle(snap);
        } else {
            DBG("TH32CS_SNAPMODULE failed\n");
        }

        if(!found) {
            snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, ret);
            if(snap) {
                if(Process32First(snap, process_entry)) {
                    do {
                        if(process_entry->th32ProcessID == ret) {
                            DBG("got process, name=%s\n", process_entry->szExeFile);
                            processName = QString::fromLocal8Bit(process_entry->szExeFile);
                            found = true;
                            break;
                        }
                    } while(Process32Next(snap, process_entry));
                }
                CloseHandle(snap);
            } else {
                DBG("TH32CS_SNAPPROCESS failed\n");
            }
        }

        free(module_entry);
        free(process_entry);
    }
#else
    AdbProcess p;
    QByteArray outstd;
    QByteArray outerr;
    p.exec_cmd("netstat -tlnp", outstd, outerr);
    QList<QByteArray> lines  = outstd.split('\n');

    bool headParsed = false;
    int pos_laddr = -1;
    int pos_state = -1;
    int pos_pid = -1;
    foreach(const QByteArray& line, lines) {
        if(line.isEmpty()) {
            continue;
        }

        if(!headParsed) {
            if(line.startsWith("Proto ")) {
                pos_laddr = line.indexOf("Local Address ");
                pos_state = line.indexOf("State ");
                pos_pid = line.indexOf("PID/Program name");
                headParsed = true;
            }
            continue;
        }

        QByteArray laddr = getNetstatArg(line, pos_laddr);
        QByteArray state = getNetstatArg(line, pos_state);
        QByteArray progname = getNetstatArg(line, pos_pid);
        if(state == "LISTEN" && laddr.endsWith(QString(":%1").arg(ADB_DEFAULT_PORT).toLocal8Bit())) {
            DBG("found target: [%s]\n", progname.data());
            if((pos_pid = progname.indexOf('/')) != -1) {
                ret = progname.left(pos_pid).toInt();
            }
            break;
        }
    }

#endif
    DBG("got adb pid [%d]\n", ret);
    return ret;
}

void AdbTracker::run() {
    core_run();
    emit sigDone(this);
}

void AdbTracker::core_run() {
    QTcpSocket socket;
    char tmp[8];
    int n, len;

    int adb_pid;
    QString adbPath;
    bool our_adb;

    QProcess::execute(adb_exe + " kill-server");
    while(!needsQuit) {
        our_adb = false;
        socket.connectToHost("127.0.0.1", ADB_DEFAULT_PORT);
        if(!socket.waitForConnected(500)) {
            socket.abort();
            our_adb = true;
            DBG("start our_adb = true\n");

            bool success = false;
            for(int retry=0; retry<5; retry++) {
                DBG("retry %d\n", retry+1);
                QProcess::execute(adb_exe + " start-server");

                socket.connectToHost("127.0.0.1", ADB_DEFAULT_PORT);
                if(!socket.waitForConnected(500)) {
                    socket.abort();
                    msleep(500);

                    adb_pid = getAdbPid(adbPath);
                    if(adb_pid != -1) {
#ifdef _WIN32
                        HANDLE p = OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE, FALSE, adb_pid);
                        if(p != NULL) TerminateProcess(p, 0);
#else
                        QProcess::execute(QString("kill %1").arg(adb_pid));
#endif
                    }
                    continue;
                }
                success = true;
                break;
            }

            if(!success) {
                emit sigAdbError(tr("connect adb host fail!"), -2);
                return;
            }
        }

        adbPath = tr("unknown");
        adb_pid = getAdbPid(adbPath);
        if(!writex(&socket, "host:track-devices") || readx(&socket, 4) != "OKAY") {
            emit sigAdbError(tr("adb track-devices fail!")
                             + tr("\nConflict process name: %1").arg(adbPath), adb_pid);
            return;
        }

        AdbNurse t(this, adb_pid);
        t.start();

        DBG("start tracking...\n");
        while(!needsQuit) {
            socket.waitForReadyRead(200);
            if((n = socket.read(tmp, 4)) != 4) {
                if(n < 0 || adbHanged) {
                    break;
                }
                continue;
            }

            sscanf(tmp, "%04X", &len);
            DBG("got len %d\n", len);
            QByteArray buf = socket.read(len);
            refreshDeviceList(buf);
            emit sigDevListChanged();
        }
        socket.disconnectFromHost();
        DBG("track finished.\n");

        foreach(AdbDeviceNode *node, deviceList) {
            node->connect_statname = "disconnected";
            node->connect_stat = AdbDeviceNode::CS_DISCONNECTED;
        }
        emit sigDevListChanged();
        t.stop();
        t.wait();
    }

    if(our_adb) {
        DBG("send kill-server to our adb\n");
        QProcess::execute(adb_exe + " kill-server");
    }
}

void AdbTracker::cleanUp() {
    DBG("start cleanUp...\n");
    int new_index = 1;
    deviceList_mutex.lock();
    for(int i=0; i<deviceList.size(); i++) {
        AdbDeviceNode *node = deviceList[i];
        if(node->connect_stat == AdbDeviceNode::CS_DISCONNECTED) {
            DBG("cleaned %p\n", node);
            deviceList.removeAt(i--);
            delList.append(node);
        } else {
            node->node_index = new_index++;
        }
    }
    deviceList_mutex.unlock();

    for(int i=0; i<delList.size(); i++) {
        AdbDeviceNode *node = delList[i];
        if(node->jobThread == NULL) {
            DBG("real free %p\n", node);
            AdbDeviceNode::delDeviceNode(delList.takeAt(i--));
        }
    }
    DBG("end cleanUp...\n");
    emit sigDevListChanged();
}

void AdbTracker::freeMem() {
    while(!deviceList.isEmpty()) {
        delete deviceList.takeFirst();
    }

    while(!delList.isEmpty()) {
        delete delList.takeFirst();
    }
}

int AdbTracker::getActiveCount() {
    int count = 0;
    deviceList_mutex.lock();
    foreach(AdbDeviceNode *n, deviceList) {
        if(n->connect_stat == AdbDeviceNode::CS_DEVICE) {
            count ++;
        }
    }
    deviceList_mutex.unlock();
    return count;
}

QList<AdbDeviceNode *> AdbTracker::getDeviceList() {
    QList<AdbDeviceNode *> list;
    deviceList_mutex.lock();
    list.append(deviceList);
    deviceList_mutex.unlock();
    return list;
}
