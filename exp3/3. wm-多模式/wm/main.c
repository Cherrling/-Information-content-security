/*****************************************************************
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2012.05.11
 *
 *****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "wm.h"
#define FileNum_Char 50
#define KEYSFILE "key.txt"
#define EXPRFILE "expr.txt"
#define STRINGFILE "string.txt"

extern int nfound;

int main()
{
	FILE *fp, *proc,*ft;
	char text[4096];
	unsigned char pattern[4096];
	WM_STRUCT *p;
	int phitRuleId, pFoundPostion;
	struct timeval starttv, endtv;
	int i;
	pid_t pid;
//	int nfound=0;
	long tmp;
	unsigned long uLong;
	unsigned long long uLLong;
	unsigned int j;
	unsigned long vsize;

	p=wmNew();	//创建模式串集

	char *PatternFileName, *TextFileName;
	if((PatternFileName = (char *)malloc(FileNum_Char * sizeof(char))) == NULL)
	{
	  printf("---Error---Insufficient memory available!\n");
	  exit(-1);
	}
	if((TextFileName = (char *)malloc(FileNum_Char * sizeof(char))) == NULL)
	{
	  printf("---Error---Insufficient memory available!\n");
	  exit(-1);
	}
	memset(PatternFileName, '\0', FileNum_Char);
	memset(TextFileName, '\0', FileNum_Char);
	printf("-!-Please input patterns file name:");
	scanf("%s", PatternFileName);
	printf("-!-Please input text file name:");
	scanf("%s", TextFileName);

	fp = fopen(PatternFileName, "r");
	if(fp == NULL)
	{
		fprintf(stderr, "open %s failed\n", PatternFileName);
		exit(0);
	}
	/*i = fscanf(fp, "%s", text);
	fclose(fp);*/

	if(gettimeofday(&starttv, NULL) < 0)
	{
		fprintf(stderr, "%s:%d\tgettimeofday error\n", __FILE__, __LINE__);
		exit(0);
	}

	while(fscanf(fp,"%s",pattern)==1)
	{
		wmAddPattern(p,pattern,strlen((const char*)pattern));	//新增模式子串
//		printf("len=%u\n", (u_int32_t)strlen((const char*)pattern));
//		getchar();
	}
	fclose(fp);

	/*********************************test add pattern******************************
	WM_PATTERN_STRUCT *pl;
 	for(pl=p->plist,i=0;pl!=NULL;pl=pl->next,i++)
	{
		printf("%d %s\n",i,pl->psPat);
	}
	********************************************************************************/
	wmPrepPatterns(p);	//对模式串集预处理


	if(gettimeofday(&endtv, NULL) < 0)
	{
		fprintf(stderr, "%s:%d\tgettimeofday error\n", __FILE__, __LINE__);
		exit(0);
	}

	printf("InitSearch tasks %ld ms\n", endtv.tv_sec * 1000 + endtv.tv_usec / 1000 - starttv.tv_sec * 1000 - starttv.tv_usec / 1000);



/************************计算内存********************************/
/*	pid = getpid();
	sprintf(text, "/proc/%d/stat", pid);
	proc = fopen(text, "r");
	if(proc == NULL)
	{
		//fprintf(stderr, "get stat error\n");
		exit(0);
	}
	i = fscanf(proc, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %d", &pid, text, &text[0], &pid, &pid, &pid, &pid, &pid, &j, &uLong, &uLong, &uLong,&uLong, &uLong,&uLong, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp, &uLLong, &vsize, &tmp, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &pid, &pid, &j, &j, &uLLong, &uLong, &pid);
	fclose(proc);
	printf("内存使用了%ld MB\n", (vsize / 1024 / 1024));*/
/*****************************************************************************/


	ft = fopen(TextFileName, "r");
	if(ft == NULL)
	{
		fprintf(stderr, "open %s failed @ %s:%d\n", TextFileName,__FILE__,__LINE__);
		exit(0);
	}
	i = 0;
	gettimeofday(&starttv, NULL);
	while(fscanf(ft, "%s", text) == 1)
	{
		phitRuleId = -1;
		pFoundPostion = -1;

		wmSearch(p,(unsigned char*)text,strlen(text));

//		if(phitRuleId != -1)
//		{
//			fprintf(stderr, "hit_ruleId=%d\ttext_pos=%d\n", phitRuleId, pFoundPostion);
//			i ++;
//		}
	}
	gettimeofday(&endtv, NULL);
	printf("Search_time=%ldms\nHit_num=%d\n", endtv.tv_sec * 1000 + endtv.tv_usec / 1000 - starttv.tv_sec * 1000 - starttv.tv_usec / 1000, nfound);
	fclose(ft);
	wmFree(p);
	return 0;
}
