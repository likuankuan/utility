package api

import (
	"github.com/astaxie/beego/orm"
	"license_server/models"
	"license_server/utils"
	"sync"
)

type (
	Logger struct {
		//Level    Lvl
		Function string
		Request  string
		DeviceId string
		SrcIp    string
		Database string
		mutex    sync.Mutex
	}
	Lvl int
)

const (
	EMERGENCY Lvl = iota + 0
	AL
	CRITICAL
	ERROR
	WARN
	Notice
	INFO
	DEBUG
)

//设置日志级别
var LogLv = INFO

func NewDevLog(function string, srcIp string) (l *Logger) {
	l = &Logger{
		Function: function,
		SrcIp:    srcIp,
		Database: "dev_log",
	}

	return
}
func NewMgMtLog(function string, srcIp string) (l *Logger) {
	l = &Logger{
		Function: function,
		SrcIp:    srcIp,
		Database: "mgMt_log",
	}

	return
}

func (l *Logger) SetRequest(r string) {
	l.Request = r
}

func (l *Logger) SetDeviceId(d string) {
	l.DeviceId = d
}

func (l *Logger) Debug(ret int, msg string) error {
	err := l.WriteLog(DEBUG, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Info(ret int, msg string) error {
	err := l.WriteLog(INFO, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Notice(ret int, msg string) error {
	err := l.WriteLog(Notice, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Warn(ret int, msg string) error {
	err := l.WriteLog(WARN, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Error(ret int, msg string) error {
	err := l.WriteLog(ERROR, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Critical(ret int, msg string) error {
	err := l.WriteLog(CRITICAL, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Alert(ret int, msg string) error {
	err := l.WriteLog(AL, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) Emergency(ret int, msg string) error {
	err := l.WriteLog(EMERGENCY, ret, msg)
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) WriteLog(lvl Lvl, ret int, msg string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if lvl <= LogLv {
		switch l.Database {
		case "dev_log":
			err := WriteDevLog(lvl, l.Function, l.Request, l.DeviceId, ret, msg, l.SrcIp)
			if err != nil {
				return err
			}
		case "mgMt_log":
			err := WriteMgMtLog(lvl, l.Function, l.Request, ret, msg, l.SrcIp)
			if err != nil {
				return err
			}
		}
	}
	return nil

}

func WriteDevLog(lvl Lvl, function string, request string, deviceId string, ret int, msg string, srcIp string) error {
	o := orm.NewOrm()
	var devLog models.Dev_log
	t, err := utils.GetTime()
	if err != nil {
		return err
	}
	devLog.Time = t
	devLog.Level = int(lvl)
	devLog.Request = request
	devLog.Device_id = deviceId
	devLog.Interface = function
	devLog.Src_ip = srcIp
	devLog.Ret = ret
	devLog.Msg = msg

	_, err = o.Insert(&devLog)
	if err != nil {
		return err
	}
	return nil
}

func WriteMgMtLog(lvl Lvl, function string, request string, ret int, msg string, srcIp string) error {
	o := orm.NewOrm()
	var mgMtLog models.Mgmt_log
	t, err := utils.GetTime()
	if err != nil {
		return err
	}
	mgMtLog.Time = t
	mgMtLog.Level = int(lvl)
	mgMtLog.Request = request
	mgMtLog.Interface = function
	mgMtLog.Src_ip = srcIp
	mgMtLog.Ret = ret
	mgMtLog.Msg = msg

	_, err = o.Insert(&mgMtLog)
	if err != nil {
		return err
	}
	return nil
}
