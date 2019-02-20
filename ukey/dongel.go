package utils

/*
#cgo CFLAGS: -I../../dongel/include
#cgo LDFLAGS: -L ../../dongel/api64 -lRockeyARM
#include "Dongle_CORE.h"
#include "Dongle_API.h"
#include <stdlib.h>

int     Count;
DONGLE_INFO * pKEYList=NULL;
DONGLE_HANDLE  hKey=NULL;
*/
import "C"

import (
	"errors"
	"unsafe"
	"time"

		"license_server/models"
	"github.com/astaxie/beego/orm"
	"strconv"
)

const (
	FLAG_USERPIN  = 0 //用户PIN
	FLAG_ADMINPIN = 1 //开发商PIN

	FILE_DATA          = 1 //普通数据文件
	FILE_PRIKEY_RSA    = 2 //RSA私钥文件
	FILE_PRIKEY_ECCSM2 = 3 //ECC或者SM2私钥文件(SM2私钥文件和ECC私钥文件结构相同，属相同文件类型)
	FILE_KEY           = 4 //SM4和3DES密钥文件
	FILE_EXE           = 5 //可执行文件

)

/*************************文件授权结构***********************************/
//数据文件授权结构
type DataLic struct {
	MReadPri  C.ushort //读权限: 0为最小匿名权限，1为最小用户权限，2为最小开发商权限
	MWritePri C.ushort //写权限: 0为最小匿名权限，1为最小用户权限，2为最小开发商权限
}

//私钥文件授权结构
type PriKeyLic struct {
	MCount      C.int   //可调次数: 0xFFFFFFFF表示不限制, 递减到0表示已不可调用
	MPri      C.uchar //调用权限: 0为最小匿名权限，1为最小用户权限，2为最小开发商权限
	MIsDecOnRAM C.uchar //是否是在内存中递减: 1为在内存中递减，0为在FLASH中递减
	MIsReset    C.uchar //用户态调用后是否自动回到匿名态: TRUE为调后回到匿名态 (开发商态不受此限制)
	MReserve    C.uchar //保留,用于4字节对齐
}

//对称加密算法(SM4/TDES)密钥文件授权结构
type KeyLic struct {
	MPriEnc C.uint //加密时的调用权限: 0为最小匿名权限，1为最小用户权限，2为最小开发商权限
}

//可执行文件授权结构
type ExeLic struct {
	MPriExe C.ushort //运行的权限: 0为最小匿名权限，1为最小用户权限，2为最小开发商权限
}

/****************************文件属性结构********************************/
//数据文件属性数据结构
type DataFileAttr struct {
	MSize   C.uint //数据文件长度，该值最大为4096
	DataLic        //授权
}

//ECCSM2/RSA私钥文件属性数据结构
type PriKeyFileAttr struct {
	MType     C.ushort //数据类型:ECCSM2私钥 或 RSA私钥
	MSize     C.ushort //数据长度:RSA该值为1024或2048, ECC该值为192或256, SM2该值为0x8100
	PriKeyLic          //授权
}

//对称加密算法(SM4/TDES)密钥文件属性数据结构
type KeyFileAttr struct {
	MSize  C.uint //密钥数据长度=16
	KeyLic        //授权
}

//可执行文件属性数据结构
type ExeFileAttr struct {
	ExeLic          //授权
	MLen   C.ushort //文件长度
}

type dongel struct {
	hKey unsafe.Pointer
}

//创建dongel对象
func NewDongel() (dongel,error) {
	d := dongel{}
	_,err:=d.FindDongel()
	if err!=nil{
		return d,err
	}
	ukey, err := d.OpenDongel(0)
	if err!=nil{
		return d,err
	}
	d.hKey=ukey
	return d,nil
}

//查找dongel
//失败返回错误和错误码
//成功返回找到的个数
func (d *dongel) FindDongel() (int, error) {
	var count C.int
	retcode := C.Dongle_Enum(nil, &count)
	if retcode != 0 {
		return int(retcode), errors.New("FindDongel failed")
	}

	return int(count), nil
}

//打开指定的加密锁
//i 基于0的索引
//成功返回加密锁的句柄
func (d *dongel) OpenDongel(i int) (unsafe.Pointer, error) {
	var hkey C.DONGLE_HANDLE
	index := C.int(i)
	retCode := C.Dongle_Open(&hkey, index)
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return nil, errors.New(s)
	}
	return unsafe.Pointer(hkey), nil
}

//获取UTC时间
//hkey 打开机密锁的句柄
//成功返回时间   格式为Unix时间戳
func (d *dongel) GetUTCTime() (uint32, error) {
	var dwTime C.DWORD
	retCode := C.Dongle_GetUTCTime(C.DONGLE_HANDLE(d.hKey), &dwTime)
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return 0,errors.New(s)
	}
	return uint32(dwTime), nil
}

//校验密码
//hkey 打开机密锁的句柄
//nFLAGs PIN码类型。参考FLAG_USERPIN 用户PIN  FLAG_ADMINPIN 开发商PIN
//pPIN   PIN码（密码）
//失败返回剩余次数
func (d *dongel) VerifyPIN( nFLAGs int, pPIN string) (int, error) {

	var RemainCount C.int

	retCode := C.Dongle_VerifyPIN(C.DONGLE_HANDLE(d.hKey), C.int(nFLAGs), C.CString(pPIN), &RemainCount)
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return int(RemainCount),errors.New(s)
	}
	return int(RemainCount), nil
}

//清除PIN码验证状态。将加密锁状态变为匿名。
//hKey      打开的加密锁句柄。

func (d *dongel) ResetState() error {
	retCode := C.Dongle_ResetState(C.DONGLE_HANDLE(d.hKey))
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return errors.New(s)
	}
	return nil
}

//创建文件。该函数不支持可执行文件的创建。该操作需要开发商权限。
//hkey 打开机密锁的句柄
//nFileType        文件类型。
//                                nFileType = FILE_DATA，表示创建数据文件；对数据文件有以下说明：
//                                  1.文件大小设为252字节时,最多可创建54个文件,即占用空间13608字节
//                                   2.文件大小设为1024字节时,最多可创建31个文件，即占用空间31744字节
//                                   3.文件大小设为4096字节时，最多可创建9个文件,即占用空间36864字节
//                               nFileType = FILE_PRIKEY_RSA，表示创建RSA私钥文件；
//                               nFileType = FILE_PRIKEY_ECCSM2，表示创建ECCSM2私钥文件；
//
//                               nFileType = FILE_KEY，表示创建SM4和3DES密钥文件；
//                                不支持nFileType = FILE_EXE的文件类型。
//wFileID         文件ID。
//pFileAttr     [in]     文件的属性。参数的结构为：DATA_FILE_ATTR、PRIKEY_FILE_ATTR或KEY_FILE_ATTR。
func (d *dongel) CreateFile( nFileType int, wFileID int, pFileAttr unsafe.Pointer) error {

	retCode := C.Dongle_CreateFile(C.DONGLE_HANDLE(d.hKey), C.int(nFileType), C.ushort(wFileID), pFileAttr)
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return errors.New(s)
	}
	return nil

}

//*  写文件。该函数不支持可执行文件的写入操作，且该操作需要开发商权限。
//*
//*  hKey          打开的加密锁句柄。
//*  nFileType      文件类型。例如，
//*                                nFileType = FILE_DATA，表示创建数据文件；
//*                                nFileType = FILE_PRIKEY_RSA，表示创建RSA私钥文件；
//*                                nFileType = FILE_PRIKEY_ECCSM2，表示创建ECCSM2私钥文件；
//*                                nFileType = FILE_KEY，表示创建SM4和3DES密钥文件；
//*                                不支持nFileType = FILE_EXE的文件类型。
//*   wFileID      文件ID。
//*   wOffset      文件偏移。文件写入的起始偏移量。
//*   pInData      准备写入的数据。
//*  nDataLen      参数pInData的大小。

func (d *dongel) WriteFile(nFileType int, wFileID int, wOffset int, pInData string) error {
	l := len(pInData)
	cs := C.CString(pInData)
	defer C.free(unsafe.Pointer(cs))
	retCode := C.Dongle_WriteFile(C.DONGLE_HANDLE(d.hKey), C.int(nFileType), C.ushort(wFileID), C.ushort(wOffset), (*C.uchar)(unsafe.Pointer(cs)), C.int(l))
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return errors.New(s)
	}
	return nil
}

//读取加密锁内的数据文件。数据文件的读取权限取决于创建时的设定。
//*
//  hKey             打开的加密锁句柄。
//  wFileID          文件ID。
//  wOffset          文件偏移量。
//  pOutData         数据缓冲区。
//  nDataLen         参数pOutData的长度。

func (d *dongel) ReadFile(wFileID int, wOffset int, nDataLen int) ([]byte, error) {

	var buf = make([]C.uchar, nDataLen)

	retCode := C.Dongle_ReadFile(C.DONGLE_HANDLE(d.hKey), C.ushort(wFileID), C.ushort(wOffset), &buf[0], C.int(nDataLen))
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return nil,errors.New(s)
	}
	date := (*[]byte)(unsafe.Pointer(&buf))
	return *date, nil
	//return string(C.GoBytes(unsafe.Pointer(&buf), 4096)), nil
	//return C.GoString((*C.char)(unsafe.Pointer(&buf))), nil
}
//* 删除文件。需要开发商权限。
//*
//* hKey               打开的加密锁句柄。
//* nFileType          文件类型。
//* wFileID            文件ID。
func (d *dongel) DeleteFile(nFileType int, wFileID int) error {

	retCode := C.Dongle_DeleteFile(C.DONGLE_HANDLE(d.hKey), C.int(nFileType), C.ushort(wFileID))
	if retCode != 0 {
		return errors.New("deleteFile failed")
	}
	return nil
}

//关闭打开的加密锁。
// hKey    打开的加密锁句柄。
func (d *dongel) Close() error {
	retCode := C.Dongle_Close(C.DONGLE_HANDLE(d.hKey))
	if retCode != 0 {
		s := strconv.FormatInt(int64(retCode), 16)
		return errors.New(s)
	}
	return nil
}




//获取时间
//ukey模式，获取时间的地方都要从ukey获取
//软导模式，从本地获取时间
func GetTime()(time.Time,error)  {
	i,err:=UKeyPattern()
	if err != nil {
		return time.Date(0,0,0,0,0,0,0,time.UTC),err
	}
	if i==1{
		d,err:=NewDongel()
		if err != nil {
			return time.Date(0,0,0,0,0,0,0,time.UTC),err
		}
		t,err:=d.GetUTCTime()
		if err != nil {
			return time.Date(0,0,0,0,0,0,0,time.UTC),err
		}
		return time.Unix(int64(t),0),nil
	}else {
		return time.Now(),nil
	}
}


//判断是不是uky模式
func UKeyPattern()(int,error){
	o := orm.NewOrm()
	points := models.Points{Id: 1}
	_,_,err := o.ReadOrCreate(&points,"id")
	return points.UkeyPattern,err
}

