/*****************************************************************
*author:     xudongliang
*copyright:  www.pact518.hit.edu.cn
*date:       2014.01.02
*
*****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//URL解析，将ＵＲＬ以'/'为分隔符进行解析
int urlparse(char str[][30],char *url)
{
	int i=0;
	int j=0;

	//初始化解析数组
	for(i=0;i<30;i++)
	{
		memset(str[i],'\0',1024);
	}
//	printf("--parse--%d\n",sizeof(str[0]));

	i=0;
	while(*url)
	{
		for(;*url=='/';url++);//去掉开头的'/'

		while(*url != '\0' && *url != '/')
		{
			str[i][j++] = *url++;

			if(j>=1024)
			{
				printf("--!--The longth of component is more than 30\n");
				exit(0);
			}
		}

		if((i++) >= 30)
		{
			printf("--!--The num of component is more than 30\n");
			exit(0);
		}
		j=0;
	}
	return 0;
}



















