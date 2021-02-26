#include"mkfuzz.h"


int main(int argc, char* argv[])
{
	ARGS args;
	m_uint err_code = 0;
	m_bool status = Get_Args(argc, argv, &args);
	if (CheckArgs(&args) == m_false)
		return 0;
	////通过了参数检查，然后开始主体内容
	FuzzMain(&err_code, &args);
	//printf("%ld %ld\n%ld %ld", args.IOCTL_CODE_MIN, args.IOCTL_CODE_MAX, args.BUFF_SIZE_MIN, args.BUFF_SIZE_MAX);
	
	return 0;
}