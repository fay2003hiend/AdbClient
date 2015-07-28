#ifndef ADBPROCESS_H
#define ADBPROCESS_H

#include <QProcess>
#include <QByteArray>

class AdbProcess : public QProcess {
    Q_OBJECT
    QByteArray _stdoutData;
    QByteArray _stderrData;
public:
    AdbProcess(const QString& adb_serial = QString(), QObject *parent = 0);
    int exec_cmd(const QString& cmd, QByteArray& stdoutData, QByteArray& stderrData);
private slots:
    void slot_readStdout();
    void slot_readStderr();
};

#endif // ADBPROCESS_H
