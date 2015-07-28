#include "adbprocess.h"

AdbProcess::AdbProcess(const QString& adb_serial, QObject *parent)
    : QProcess(parent) {
    if(!adb_serial.isEmpty()) {
        QProcessEnvironment env = this->processEnvironment();
        env.insert("ANDROID_SERIAL", adb_serial);
        setProcessEnvironment(env);
    }

    connect(this, SIGNAL(readyReadStandardOutput()), SLOT(slot_readStdout()));
    connect(this, SIGNAL(readyReadStandardError()), SLOT(slot_readStderr()));
}

int AdbProcess::exec_cmd(const QString &cmd, QByteArray &stdoutData, QByteArray &stderrData) {
    int ret = -2;
    do {
        _stdoutData.clear();
        _stderrData.clear();

        start(cmd);
        if(!waitForStarted()) {
            break;
        }

        if(!waitForFinished(-1)) {
            return -1;
        }

        ret = exitCode();
        stdoutData = _stdoutData;
        stderrData = _stderrData;
    } while(0);
    return ret;
}

void AdbProcess::slot_readStdout() {
    _stdoutData.append(this->readAllStandardOutput());
}

void AdbProcess::slot_readStderr() {
    _stderrData.append(this->readAllStandardError());
}
