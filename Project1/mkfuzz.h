#pragma once
#include<stdio.h>
#include<stdlib.h>
#include<stdarg.h>
#include<Windows.h>
#include<winioctl.h>

#define BUFF_MAX_LEN 0xffff;

#define m_int    int
#define m_uint   unsigned int
#define m_ullong unsigned long long
#define m_llong  long long
#define m_uchar  unsigned char
#define m_char   char
#define m_ushort unsigned short
#define m_bool	 m_uchar

#define MAX_BUFF_SIZE 65536

#define m_true   1
#define m_false  0

#define FLAG_ARGERROR	0
#define FLAG_HELP		1
#define FLAG_OK			2

typedef struct __ARGS
{
	m_char path[512];									////内核驱动符号地址
	m_uchar conf_path[512];								////配置文件路径
	m_uchar buff_file_path[512];						////指定用例存放文件路径
	m_ullong IOCTL_CODE;								////指定的ioctl code
	m_ullong IOCTL_CODE_MIN;							////存放指定的ioctl code区间最小值
	m_ullong IOCTL_CODE_MAX;							////存放指定的ioctl code区间最大值
	m_ullong BUFF_SIZE_MIN;								////指定BUFF长度区间最小长度
	m_ullong BUFF_SIZE_MAX;								////指定BUFF长度区间最大长度
	m_bool help;										////帮助参数
}ARGS, *PARGS;

typedef struct __CONF_ARGS
{
	m_uchar master_ip;
	m_ushort master_port;
};

typedef struct __IOCTL_CODE_LIST
{
	m_ullong ioctl_code;								////IOCTL CODE
	m_ullong buff_size_max;								////最大buff长度
	m_ullong buff_size_min;								////最小buff长度
	m_ullong err_code;									////错误码
}IOCTL_CODE_LIST, *PIOCTL_CODE_LIST;

////检查参数合法性
m_bool CheckArgs(_In_ PARGS args);

////主要功能实现函数
m_bool FuzzMain(_Inout_ m_uint* err_code, _In_ PARGS args);

////获取内核驱动句柄
HANDLE __get_device_handle(_In_ m_char* path, _Inout_ m_ullong* err_code);

////探测有效的IOCTL CODE与buff长度
m_bool __get_ioctl_list(_In_ PARGS args, _In_ HANDLE device_handle,
	_Inout_ PIOCTL_CODE_LIST list, _In_ m_uint src_count, _Inout_ m_uint* list_count
);

////打印帮助信息
void __print_help(_In_ m_uchar flag);

////打印报错信息
void __print_error_info(_In_ m_llong err_code);

////解析配置文件获取必要环境变量
m_uchar __get_configure_args(_In_ m_uchar* path);

////输入参数地址随机化探测
m_bool __inbuff_address(_In_ IOCTL_CODE_LIST ioctl_list);

////buff长度探测
void __buff_len(_In_ IOCTL_CODE_LIST ioclt_list, _Inout_ m_uint* inMax, _Inout_ m_uint* inMin,
	_Inout_ m_uint* outMax, _Inout_ m_uint* outMin);

////输入数据随机化探测，即可基于生成然后进行变异，也可输入指定语料然后进行变异
m_bool __inbuff_data(_In_ IOCTL_CODE_LIST ioctl_list);

////输出参数地址随机化探测
m_bool __outbuff_address(_In_ IOCTL_CODE_LIST ioctl_list);

////输出数据随机化探测
m_bool __outbuff_data(_In_ IOCTL_CODE_LIST ioctl_list);

////此函数用于获取命令行参数
m_uchar Get_Args(_In_ int argc, _In_ char* argv[], _Inout_ PARGS args);
