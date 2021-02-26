#include"mkfuzz.h"

void __print_help(_In_ m_uchar flag)
{
	puts(" ___________ __  __     ______ __   __  ____  ____   ");
	puts("|   _   _   |  |/  /   |  ____]  | |  |[__  ][__  ]");
	puts("|  | | | |  |  [  (    |  ____]  |_|  |  / /_  / /_");
	puts("|__| |_| |__|__|\\__\\   |__|   |_______| [____][____]   v1.0");
	puts("");
	puts("		 AUTHOR: Anansi	");
	puts("	EMAIL: pluviophile12138@outlook.com	");
	puts("		LICENSES: GPL v3.0");
	puts("\n");
	if (flag == FLAG_HELP)
	{
		puts("\rUsage:");
		puts("---------------------------------------");
		puts("\rmkfuzz  -p<\\\\.\\xxxxx> \n\t-c<Conf path>\n\t(-i<code>|-ir<code-code>)");
		puts("\t[-sr<size-size>]\n\t[-b<buff path>]");
		puts("\t[-h]");
		puts("\n");
		puts("\rOptions:");
		puts("---------------------------------------");
		puts("\r-p --path\t\t内核驱动符号链接地址，需要加上\\\\.\\");
		puts("\r-c --conf\t\t配置文件加载路径");
		puts("\r-b --buff-file\t\t用例文件加载路径");
		puts("\r-i --ioctl-code\t\t指定ioctl code");
		puts("\r-h --help\t\t帮助信息");
		puts("\r-ir --ioctl-rate\tioctl code区间，注意此处填写十六进制数");
		puts("\r-sr --buffsize-rate\t用例长度区间");
		
	}
	if (flag == FLAG_ARGERROR)
		puts("\r[*]请输入正确的使用参数!");
	return;
}

HANDLE __get_device_handle(_In_ m_char* path, _Inout_ m_ullong* err_code)
{
	HANDLE device_handle = CreateFileA(path,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (device_handle == INVALID_HANDLE_VALUE)
	{
		*err_code = GetLastError();
		return NULL;
	}
	return device_handle;
}

void __print_error_info(_In_ m_llong err_code)
{
	switch (err_code)
	{
	case ERROR_FILE_NOT_FOUND:
		puts("\n\r[!]句柄打开失败，目标不存在!");
		break;
	case ERROR_ACCESS_DENIED:
		puts("\n\r[!]无访问权限!");
		break;
	case ERROR_NOT_SUPPORTED:
		puts("\n\r[!]不支持该请求!");
		break;
	case ERROR_INSUFFICIENT_BUFFER:
		puts("\n\r[!]传递的数据区过小");
		break;
	default:
		break;
	}
}

m_bool __get_ioctl_list(_In_ PARGS args, _In_ HANDLE device_handle,
	_Inout_ PIOCTL_CODE_LIST list, _In_ m_uint src_count, _Inout_ m_uint* list_count
)
{
	m_uint status = 0;
	DWORD pOutBuffSize = 0;
	m_uchar inputBuff[MAX_BUFF_SIZE];
	m_uchar outputBuff[MAX_BUFF_SIZE];
	memset(inputBuff, 0x00, MAX_BUFF_SIZE);
	memset(outputBuff, 0x00, MAX_BUFF_SIZE);
	memset(list, 0x00, src_count);

	////如果设置了具体的IOCTL CODE那就只去处理IOCTL CODE
	if (args->IOCTL_CODE)
	{
		m_ullong code = 0;
		////此处可能存在空指针引用，但此处无法设计日志功能需要手动使用windbg去调试
		status = DeviceIoControl(device_handle,
			args->IOCTL_CODE,
			NULL,
			0,
			NULL,
			0,
			&pOutBuffSize,
			NULL);
		if (!status)
		{
			code = GetLastError();
			if ((code == ERROR_ACCESS_DENIED) || (code == ERROR_NOT_SUPPORTED))
			{
				*list_count = 0;
				list[0].buff_size_max = 0;
				list[0].buff_size_min = 0;
				list[0].ioctl_code = 0;
				list[0].err_code = code;
				return m_false;
			}
		}
		*list_count = 1;
		list[0].buff_size_max = 0;
		list[0].buff_size_min = 0;
		list[0].err_code = code;
		list[0].ioctl_code = args->IOCTL_CODE;
		return m_true;
	}
	////按照区间去依次测试可用IOCTL CODE
	if ((args->IOCTL_CODE_MIN) < (args->IOCTL_CODE_MAX))
	{
		m_uint index = 0;
		for (m_ullong i = args->IOCTL_CODE_MIN; i <= args->IOCTL_CODE_MAX; i++)
		{
			status = DeviceIoControl(device_handle,
				i,
				NULL,
				0,
				NULL,
				0,
				&pOutBuffSize,
				NULL);
			if (!status)
			{
				m_uint code = GetLastError();
				//// ERROR_ACCESS_DENIED代表无权访问，如果使用管理员权限也无权访问那就可以抛弃了
				//// ERROR_NOT_SUPPORTED代表不支持此请求，即IOCTL CODE不正确
				if ((code != ERROR_ACCESS_DENIED) && (code != ERROR_NOT_SUPPORTED))
				{
					list[index].ioctl_code = i;
					list[index].buff_size_max = 0;
					list[index].buff_size_min = 0;
					list[index].err_code = code;
					index++;
				}
			}
		}
		*list_count = index;
		return m_true;
	}
	else
	{
		__print_help(2);
		return m_false;
	}
	return m_true;
}

m_bool __inbuff_address(_In_ IOCTL_CODE_LIST ioctl_list)
{
	return m_true;
}

void __buff_len(_In_ IOCTL_CODE_LIST ioclt_list, _Inout_ m_uint* inMax, _Inout_ m_uint* inMin,
	_Inout_ m_uint* outMax, _Inout_ m_uint* outMin)
{
	;
}

m_bool Get_Args(_In_ int argc, _In_ char* argv[], _Inout_ PARGS args)
{
	memset(args, 0x00, sizeof(ARGS));
	for (int i = 1; i < argc; i += 2)
	{
		////字符串参数处理
		////内核驱动符号链接参数
		if ((!strcmp(argv[i], "-p")) || (!strcmp(argv[i], "-P")) || (!strcmp(argv[i], "--path")))
		{
			if (argv[i + 1])
			{
				memcpy(args->path, argv[i + 1], strlen(argv[i + 1]));
				args->path[strlen(argv[i + 1])] = '\0';
			}
		}
		////配置文件路径参数
		if ((!strcmp(argv[i], "-c")) || (!strcmp(argv[i], "-C")) || (!strcmp(argv[i], "--conf")))
		{
			if (argv[i + 1])
			{
				memcpy(args->conf_path, argv[i + 1], strlen(argv[i + 1]));
				args->conf_path[strlen(argv[i + 1])] = '\0';
			}
		}
		////用例文件保存路径
		if ((!strcmp(argv[i], "-b")) || (!strcmp(argv[i], "-B")) || (!strcmp(argv[i], "--buff-file")))
		{
			if (argv[i + 1])
			{
				memcpy(args->buff_file_path, argv[i + 1], strlen(argv[i + 1]));
				args->buff_file_path[strlen(argv[i + 1])] = '\0';
			}
		}

		////整形参数处理
		////IOCTL CODE参数
		if ((!strcmp(argv[i], "-i")) || (!strcmp(argv[i], "-I")) || (!strcmp(argv[i], "--ioctl-code")))
		{
			char* end_str;
			if (argv[i + 1])
				args->IOCTL_CODE = strtol(argv[i + 1], &end_str, 16);
		}

		////整形区间参数处理
		////IOCTL CODE区间处理
		if ((!strcmp(argv[i], "-ir")) || (!strcmp(argv[i], "-IR")) || (!strcmp(argv[i], "--ioctl-rate")))
		{
			if (argv[i + 1])
			{
				char* index = strchr(argv[i + 1], '-');
				char* end_str;
				index[0] = '\0';
				index++;
				char* min = argv[i + 1];
				char* max = index;
				args->IOCTL_CODE_MIN = strtol(min, &end_str, 16);
				args->IOCTL_CODE_MAX = strtol(max, &end_str, 16);
			}
		}
		////BUFF SIZE区间处理
		if ((!strcmp(argv[i], "-sr")) || (!strcmp(argv[i], "-SR")) || (!strcmp(argv[i], "--buffsize-rate")))
		{
			if (argv[i + 1])
			{
				char* index = strchr(argv[i + 1], '-');
				index[0] = '\0';
				index++;
				char* min = argv[i + 1];
				char* max = index;
				args->BUFF_SIZE_MIN = atoll(min);
				args->BUFF_SIZE_MAX = atoll(max);
			}
		}
		if ((!strcmp(argv[i], "-h")) || (!strcmp(argv[i], "-H")) || (!strcmp(argv[i], "--help")))
			args->help = m_true;
		
	}
	return m_true;
}

m_bool FuzzMain(_Inout_ m_uint * err_code, _In_ PARGS args)
{
	puts("------------------------------------------------------------------");
	m_uint ioctl_count = 0;
	m_uint out_count = 0;
	if (args->IOCTL_CODE)
		ioctl_count = 1;
	else
		ioctl_count = (args->IOCTL_CODE_MAX) - (args->IOCTL_CODE_MIN);
	m_ullong err_code_tmp = 0;
	PIOCTL_CODE_LIST ioctl_list = (PIOCTL_CODE_LIST)malloc(ioctl_count * sizeof(IOCTL_CODE_LIST));
	if (ioctl_list == NULL)
	{
		printf("[!]内存申请失败!");
		exit(-1);
	}

	printf("\n\r[*]获取目标句柄:%s", args->path);
	HANDLE device_handle = __get_device_handle(args->path,&err_code_tmp);
	if (!device_handle)
	{
		__print_error_info(err_code_tmp);
		return m_false;
	}
	printf("\n\r[*]探测IOCTL CODE中...");
	__get_ioctl_list(args, device_handle, ioctl_list, ioctl_count, &out_count);
	printf("\n\r[*]可用IOCTL:");
	printf("\n\r+-------------------------------------------------------+");
	printf("\n\r|	id	|	ioctl code	|   error code  |");
	printf("\n\r+-------------------------------------------------------+");
	for (int i = 0; i < out_count; i++)
	{
		printf("\n\r|	%d	|	0x%lx	|	 %d 	|", i, ioctl_list[i].ioctl_code, ioctl_list[i].err_code);
	}
	m_uint curr_index = 0;
	printf("\n\r+-------------------------------------------------------+");
	printf("\n\r>根据id选择一个IOCTL进行测试\n\r>");
	scanf_s("%d", &curr_index);
	CloseHandle(device_handle);
	free(ioctl_list);
	return m_true;
}

m_bool CheckArgs(_In_ PARGS args)
{
	if (args->help)
	{
		__print_help(FLAG_HELP);
		return m_false;
	}
	else
	{
		if (args->path[0] == '\0')
		{
			__print_help(FLAG_ARGERROR);
			return m_false;
		}
		if ((!args->IOCTL_CODE) && ((!args->IOCTL_CODE_MIN) && (!args->IOCTL_CODE_MAX)))
		{
			__print_help(FLAG_ARGERROR);
			return m_false;
		}
		if (args->IOCTL_CODE_MIN > args->IOCTL_CODE_MAX)
		{
			__print_help(FLAG_ARGERROR);
			return m_false;
		}
		if (args->BUFF_SIZE_MIN > args->BUFF_SIZE_MAX)
		{
			__print_help(FLAG_ARGERROR);
			return m_false;
		}
		////如果没有设置buff长度或者buff长度区间，那就使用默认值设定区间
		if (((!args->BUFF_SIZE_MIN) && (!args->BUFF_SIZE_MAX)))
		{
			args->BUFF_SIZE_MIN = 1;
			args->BUFF_SIZE_MAX = BUFF_MAX_LEN;
		}
	}
	__print_help(FLAG_OK);
	return m_true;
}
