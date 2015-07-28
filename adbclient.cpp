#include "adbclient.h"

#include <QFile>
#include <QDateTime>
#include "zlog.h"

#define htoll(x) (x)
#define ltohl(x) (x)
#define MKID(a,b,c,d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

#define ID_STAT MKID('S','T','A','T')
#define ID_LIST MKID('L','I','S','T')
#define ID_ULNK MKID('U','L','N','K')
#define ID_SEND MKID('S','E','N','D')
#define ID_RECV MKID('R','E','C','V')
#define ID_DENT MKID('D','E','N','T')
#define ID_DONE MKID('D','O','N','E')
#define ID_DATA MKID('D','A','T','A')
#define ID_OKAY MKID('O','K','A','Y')
#define ID_FAIL MKID('F','A','I','L')
#define ID_QUIT MKID('Q','U','I','T')

typedef union {
    unsigned id;
    struct {
        unsigned id;
        unsigned namelen;
    } req;
    struct {
        unsigned id;
        unsigned mode;
        unsigned size;
        unsigned time;
    } stat;
    struct {
        unsigned id;
        unsigned mode;
        unsigned size;
        unsigned time;
        unsigned namelen;
    } dent;
    struct {
        unsigned id;
        unsigned size;
    } data;
    struct {
        unsigned id;
        unsigned msglen;
    } status;
} syncmsg;

#define SYNC_DATA_MAX 64*1024
typedef struct {
    unsigned id;
    unsigned size;
    char data[SYNC_DATA_MAX];
} syncsendbuf;

AdbClient::AdbClient(const QString &adb_serial, int port) {
    this->_adb_serial = adb_serial;
    this->_port = port;
    this->_socket = NULL;
}

AdbClient::~AdbClient() {
    adb_close();
}

bool AdbClient::init_tmpdir() {
    adb_cmd("shell:mkdir /data/local;mkdir /data/local/tmp;chmod 777 /data/local/tmp");

    QByteArray out = adb_cmd("shell:echo > /data/local/tmp/.adb_client_tag; echo TAG_RET=$?");
    if(out.contains("TAG_RET=0")) {
        _adb_tmpdir = "/data/local/tmp";
    } else {
        out = adb_cmd("shell:echo > /data/local/.adb_client_tag; echo TAG_RET=$?");
        if(out.contains("TAG_RET=0")) {
            _adb_tmpdir = "/data/local";
        } else {
            DBG("cannot find valid tmp dir!\n");
            return false;
        }
    }
    DBG("found tmpdir '%s'\n", _adb_tmpdir.toLocal8Bit().data());
    return true;
}

bool AdbClient::readx(char *buf, int len, int timeout) {
    if(_socket != NULL && _socket->state() == QTcpSocket::ConnectedState) {
        int pos = 0;
        int n = -1;
        int retry = 0;
        while(pos < len) {
            _socket->waitForReadyRead(timeout);
            n = _socket->read(buf + pos, len - pos);
            if(n > 0) {
                pos += n;
            } else if(_socket->state() != QTcpSocket::ConnectedState) {
                break;
            } else if(retry++ == 10) {
                break;
            }
        }
        if(retry > 1) {
            DBG("tried %d times @ timeout %d\n", retry, timeout);
        }
        if(pos != len) {
            DBG("read %d / %d\n", pos, len);
            return false;
        }
        return true;
    }
    return false;
}

bool AdbClient::writex(char *buf, int len) {
    if(_socket != NULL && _socket->state() == QTcpSocket::ConnectedState) {
        int pos = 0;
        int n = -1;
        while(pos < len) {
            n = _socket->write(buf + pos, len - pos);
            if(n > 0) {
                pos += n;
            } else {
                break;
            }
            _socket->waitForBytesWritten();
        }
        return pos == len;
    }
    return false;
}

void AdbClient::sync_quit() {
    syncmsg msg;
    msg.req.id = ID_QUIT;
    msg.req.namelen = 0;

    writex((char *)&msg.req, sizeof(msg.req));
}

bool AdbClient::adb_status() {
    char buf[8] = {0};
    unsigned long len;
    bool ret = false;

    do {
        if(!readx(buf, 4)) {
            break;
        }

        if(!memcmp(buf, "OKAY", 4)) {
            ret = true;
            break;
        }

        if(memcmp(buf, "FAIL", 4)) {
            break;
        }

        if(!readx(buf, 4)) {
            break;
        }

        buf[4] = 0;
        len = strtoul(buf, 0, 16);
        QByteArray err = _socket->read(len);
        _adb_error = QString::fromUtf8(err.data(), err.size());
        DBG("adb_err: '%s'\n", err.data());
    } while(0);
    return ret;
}

bool AdbClient::switch_socket_transport() {
    QString service;
    if(_adb_serial.isEmpty()) {
        service = "host:transport-any";
    } else {
        service = "host:transport:" + _adb_serial;
    }

    char tmp[8];
    int len = service.length();
    sprintf(tmp, "%04x", len);

    if(!writex(tmp, 4) || !writex(service.toUtf8().data(), len)) {
        return false;
    }

    return adb_status();
}

bool AdbClient::adb_connect(const QString &service) {
    DBG("adb_connect <%s>\n", service.toLocal8Bit().data());
    bool ret = false;
    char tmp[8];
    int len = service.toUtf8().length();
    if(len < 1 || len > 1024) {
        return false;
    }
    sprintf(tmp, "%04x", len);

    adb_close();
    _socket = new QTcpSocket();
    _socket->connectToHost("127.0.0.1", _port);
    if(!_socket->waitForConnected(500)) {
        _socket->abort();
        delete _socket;
        _socket = NULL;
        _adb_error = "cannot connect to adb host";
        return false;
    }

    do {
        if(!service.startsWith("host") && !switch_socket_transport()) {
            break;
        }

        if(!writex(tmp, 4) || !writex(service.toUtf8().data(), len)) {
            break;
        }

        ret = adb_status();
    } while(0);

    if(!ret) {
        adb_close();
    }
    return ret;
}

void AdbClient::adb_close() {
    if(_socket != NULL) {
        _socket->disconnectFromHost();
        delete _socket;
        _socket = NULL;
    }
}

QByteArray AdbClient::adb_query(const QString &service) {
    QByteArray ret;
    char buf[8] = {0};
    unsigned long len;

    do {
        if(!adb_connect(service)) {
            break;
        }

        if(!readx(buf, 4)) {
            break;
        }

        buf[4] = 0;
        len = strtoul(buf, 0, 16);
        ret = _socket->read(len);
    } while(0);
    DBG("adb_query got: '%s'\n", ret.toHex().data());
    return ret;
}

QByteArray AdbClient::adb_cmd(const QString &cmd, int timeout) {
    QByteArray ret;
    do {
        if(!adb_connect(cmd)) {
            break;
        }

        while(_socket->waitForReadyRead(timeout)) {
            ret.append(_socket->readAll());
        }
    } while(0);
    DBG("adb_cmd got: '%s'\n", ret.data());
    return ret;
}

QByteArray AdbClient::pm_cmd(const QString &cmd, int timeout) {
    QString real_cmd = QString("shell:CLASSPATH=/system/framework/pm.jar "
                               "app_process /system/bin com.android.commands.pm.Pm ") + cmd;
    return adb_cmd(real_cmd, timeout);
}

bool AdbClient::adb_install(const QString &lpath, const QString& params) {
    bool ret = false;
    if(_adb_tmpdir.isEmpty() && !init_tmpdir()) {
        return false;
    }

    qsrand(QDateTime::currentDateTime().toTime_t());
    int ran = qrand() % 0xFFFF;

    QString rpath = QString("%1/%2.apk").arg(_adb_tmpdir).arg(ran);
    if(!adb_push(lpath, rpath, 0644)) {
        DBG("cannot push apk file to '%s'!\n", rpath.toLocal8Bit().data());
        return false;
    }

    QString cmd = QString("install %1 %2").arg(params, rpath);
    QByteArray out = pm_cmd(cmd);

    if(out.contains("Success")) {
        ret = true;
    } else {
        int l = out.indexOf("Failure [");
        int r = -1;
        if(l != -1) {
            l += 9;
            r = out.indexOf(']', l);
        }
        if(r != -1) {
            _adb_error = out.mid(l, r-l);
        } else {
            _adb_error = "unknown error";
        }
    }
    if(!ret) {
        DBG("_adb_error: '%s'\n", _adb_error.toLocal8Bit().data());
    }

    cmd = QString("shell:rm %1").arg(rpath);
    adb_cmd(cmd);
    return ret;
}

bool AdbClient::adb_forward(const QString &local, const QString &remote) {
    QString service;
    if(_adb_serial.isEmpty()) {
        service = QString("host:forward:%1;%2").arg(local, remote);
    } else {
        service = QString("host-serial:%1:forward:%2;%3").arg(_adb_serial, local, remote);
    }
    return adb_connect(service) && adb_status();
}

bool AdbClient::adb_push(const QString &lpath, const QString &rpath, int mode) {
    bool ret = false;
    syncmsg msg;
    syncsendbuf sbuf;
    char buf[512];
    int len;

    QFile f(lpath);
    if(!f.open(QIODevice::ReadOnly)) {
        DBG("cannot read local file!\n");
        return false;
    }

    if(!adb_connect("sync:")) {
        f.close();
        return false;
    }

    do {
        sprintf(buf, "%s,%d", rpath.toUtf8().data(), mode);
        len = strlen(buf);
        msg.req.id = ID_SEND;
        msg.req.namelen = len;
        if(!writex((char *)&msg.req, sizeof(msg.req)) || !writex(buf, len)) {
            f.close();
            break;
        }

        ret = true;
        sbuf.id = ID_DATA;
        while((len = f.read(sbuf.data, SYNC_DATA_MAX)) > 0) {
            sbuf.size = len;
            if(!writex((char *)&sbuf, sizeof(unsigned)*2 + len)) {
                ret = false;
                break;
            }
        }
        f.close();

        msg.data.id = ID_DONE;
        msg.data.size = QDateTime::currentDateTime().toTime_t();
        if(!writex((char *)&msg.data, sizeof(msg.data))) {
            ret = false;
            break;
        }

        if(!readx((char *)&msg.status, sizeof(msg.status))) {
            break;
        }

        if(msg.status.id != ID_OKAY) {
            ret = false;
            if(msg.status.id == ID_FAIL) {
                len = msg.status.msglen;
                QByteArray err = _socket->read(len);
                _adb_error = QString::fromUtf8(err.data(), err.size());
            } else {
                _adb_error = "unknown error";
            }
        }
    } while(0);

    if(!ret) {
        DBG("_adb_error: '%s'\n", _adb_error.toLocal8Bit().data());
    }

    sync_quit();
    DBG("push done\n");
    return ret;
}

bool AdbClient::adb_pull(const QString &rpath, const QString &lpath) {
    bool ret = false;
    syncmsg msg;
    syncsendbuf sbuf;
    int len;
    unsigned id = ID_RECV;

    QFile f(lpath);
    f.remove();
    if(!f.open(QIODevice::WriteOnly)) {
        DBG("cannot write local file!\n");
        return false;
    }

    if(!adb_connect("sync:")) {
        f.close();
        return false;
    }

    do {
        msg.req.id = ID_RECV;
        msg.req.namelen = rpath.toUtf8().size();
        if(!writex((char *)&msg.req, sizeof(msg.req)) || !writex(rpath.toUtf8().data(), msg.req.namelen)) {
            break;
        }

        for(;;) {
            if(!readx((char *)&msg.data, sizeof(msg.data))) {
                break;
            }
            id = msg.data.id;
            len = msg.data.size;

            if(id == ID_DONE) {
                f.close();
                break;
            }
            if(id != ID_DATA) {
                f.close();
                f.remove();
                break;
            }

            if(!readx(sbuf.data, len)) {
                f.close();
                break;
            }

            if(f.write(sbuf.data, len) != len) {
                f.close();
                break;
            }
        }
        ret = id == ID_DONE;
    } while(0);

    if(id == ID_FAIL) {
        len = msg.data.size;
        QByteArray err = _socket->read(len);
        _adb_error = QString::fromUtf8(err.data(), err.size());
    } else if(!ret) {
        _adb_error = "unknown error";
    }

    if(!ret) {
        DBG("_adb_error: '%s'\n", _adb_error.toLocal8Bit().data());
    }

    sync_quit();
    DBG("pull done\n");
    return ret;
}

bool AdbClient::adb_pushData(unsigned char *data, int size, const QString &rpath, int mode) {
    bool ret = false;
    syncmsg msg;
    syncsendbuf sbuf;
    char buf[512];
    int pos = 0;
    int left = size;
    int len;

    if(!adb_connect("sync:")) {
        return false;
    }

    do {
        sprintf(buf, "%s,%d", rpath.toUtf8().data(), mode);
        len = strlen(buf);
        msg.req.id = ID_SEND;
        msg.req.namelen = len;
        if(!writex((char *)&msg.req, sizeof(msg.req)) || !writex(buf, len)) {
            break;
        }

        ret = true;
        sbuf.id = ID_DATA;
        while(left > 0) {
            len = left > SYNC_DATA_MAX ? SYNC_DATA_MAX : left;
            memcpy(sbuf.data, data + pos, len);
            pos += len;
            left -= len;

            sbuf.size = len;
            if(!writex((char *)&sbuf, sizeof(unsigned)*2 + len)) {
                ret = false;
                break;
            }
        }

        msg.data.id = ID_DONE;
        msg.data.size = QDateTime::currentDateTime().toTime_t();
        if(!writex((char *)&msg.data, sizeof(msg.data))) {
            ret = false;
            break;
        }

        if(!readx((char *)&msg.status, sizeof(msg.status))) {
            break;
        }

        if(msg.status.id != ID_OKAY) {
            ret = false;
            if(msg.status.id == ID_FAIL) {
                len = msg.status.msglen;
                QByteArray err = _socket->read(len);
                _adb_error = QString::fromUtf8(err.data(), err.size());
            } else {
                _adb_error = "unknown error";
            }
        }
    } while(0);

    if(!ret) {
        DBG("_adb_error: '%s'\n", _adb_error.toLocal8Bit().data());
    }

    sync_quit();
    DBG("pushData done\n");
    return ret;
}

bool AdbClient::adb_pullData(const QString &rpath, QByteArray &dest) {
    bool ret = false;
    syncmsg msg;
    syncsendbuf sbuf;
    int len;
    unsigned id = ID_RECV;

    if(!adb_connect("sync:")) {
        return false;
    }

    do {
        msg.req.id = ID_RECV;
        msg.req.namelen = rpath.toUtf8().size();
        if(!writex((char *)&msg.req, sizeof(msg.req)) || !writex(rpath.toUtf8().data(), msg.req.namelen)) {
            break;
        }

        for(;;) {
            if(!readx((char *)&msg.data, sizeof(msg.data))) {
                break;
            }
            id = msg.data.id;
            len = msg.data.size;

            if(id == ID_DONE) {
                break;
            }
            if(id != ID_DATA) {
                break;
            }

            if(!readx(sbuf.data, len)) {
                break;
            }

            dest.append((char *)sbuf.data, len);
        }
        ret = id == ID_DONE;
    } while(0);

    if(id == ID_FAIL) {
        len = msg.data.size;
        QByteArray err = _socket->read(len);
        _adb_error = QString::fromUtf8(err.data(), err.size());
    } else if(!ret) {
        _adb_error = "unknown error";
    }

    if(!ret) {
        DBG("_adb_error: '%s'\n", _adb_error.toLocal8Bit().data());
    }

    sync_quit();
    DBG("pullData done\n");
    return ret;
}

#define DDMS_RAWIMAGE_VERSION 1
typedef struct FRAMEBUFFER_HEAD {
    unsigned int version;
    unsigned int bpp;
    unsigned int size;
    unsigned int width;
    unsigned int height;
    unsigned int red_offset;
    unsigned int red_length;
    unsigned int blue_offset;
    unsigned int blue_length;
    unsigned int green_offset;
    unsigned int green_length;
    unsigned int alpha_offset;
    unsigned int alpha_length;
} FRAMEBUFFER_HEAD;

typedef struct ARGB32 {
    unsigned char b;
    unsigned char g;
    unsigned char r;
    unsigned char a;
} ARGB32;

static void convert_ARGB32(char *data, int pixels, int ao, int ro, int go, int bo) {
    ARGB32 ret;
    int src;

    int i = 0;
    int pos = 0;
    while(i++ < pixels) {
        memcpy(&src, data + pos, 4);
        ret.a = 0xff;
        ret.r = (src >> ro) & 0xff;
        ret.g = (src >> go) & 0xff;
        ret.b = (src >> bo) & 0xff;
        memcpy(data + pos, &ret, 4);

        pos += 4;
    }
}

#ifndef NO_GUI
QImage AdbClient::adb_screencap() {
    QImage ret;
    QImage::Format fmt = QImage::Format_Invalid;
    FRAMEBUFFER_HEAD head;

    do {
        if(!adb_connect("framebuffer:")) {
            break;
        }

        if(!readx((char *)&head, sizeof(head), 5000)) {
            break;
        }

        DBG("version = %d\n", head.version);
        DBG("A R G B = %02d %02d %02d %02d\n",
            head.alpha_offset,
            head.red_offset,
            head.green_offset,
            head.blue_offset);
        DBG("          %2d %2d %2d %2d\n",
            head.alpha_length,
            head.red_length,
            head.green_length,
            head.blue_length);
        DBG("width = %d, height = %d\n",
            head.width,
            head.height);
        DBG("bpp = %d, size = %d\n", head.bpp, head.size);

        char *buf = (char *)malloc(head.size);
        if(!readx(buf, head.size, 5000)) {
            free(buf);
            break;
        }

        if(head.bpp == 16) {
            fmt = QImage::Format_RGB16;
        } else if(head.bpp == 32) {
            fmt = QImage::Format_ARGB32;
            convert_ARGB32(buf, head.width*head.height,
                           head.alpha_offset,
                           head.red_offset,
                           head.green_offset,
                           head.blue_offset);
        }

        ret = QImage((uchar *)buf, head.width, head.height, fmt).copy();
        free(buf);
    } while(0);
    return ret;
}
#endif
