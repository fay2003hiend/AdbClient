#ifndef ADBCLIENT_H
#define ADBCLIENT_H

#include <QTcpSocket>
#include <QByteArray>
#ifndef NO_GUI
#include <QImage>
#endif

#define DEFAULT_ADB_PORT 5037

class AdbClient {
    QString _adb_serial;
    QString _adb_error;
    QString _adb_tmpdir;
    int _port;
    QTcpSocket *_socket;

    bool readx(char *buf, int len, int timeout = 500);
    bool writex(char *buf, int len);

    void sync_quit();
    bool adb_status();
    bool switch_socket_transport();
public:
    AdbClient(const QString& adb_serial = QString(), int port = DEFAULT_ADB_PORT);
    ~AdbClient();

    bool init_tmpdir();

    inline QTcpSocket *getSocket() {
        return _socket;
    }

    inline QString getLastError() {
        return _adb_error;
    }

    inline QString getTmpdir() {
        return _adb_tmpdir;
    }

    bool adb_connect(const QString& service);
    void adb_close();

    QByteArray adb_query(const QString& service);
    QByteArray adb_cmd(const QString& cmd, int timeout = -1);
    QByteArray pm_cmd(const QString& cmd, int timeout = -1);
    bool adb_install(const QString& lpath, const QString &params = "-r");
    bool adb_forward(const QString& local, const QString& remote);
    bool adb_push(const QString& lpath, const QString& rpath, int mode = 0644);
    bool adb_pull(const QString& rpath, const QString& lpath);
    bool adb_pushData(unsigned char *data, int size, const QString& rpath, int mode = 0644);
    bool adb_pullData(const QString& rpath, QByteArray& dest);
#ifndef NO_GUI
    QImage adb_screencap();
#endif
};

#endif // ADBCLIENT_H
