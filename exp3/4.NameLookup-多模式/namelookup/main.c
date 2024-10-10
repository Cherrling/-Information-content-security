/*****************************************************************
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2013.12.17
 *
 *****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "urlparse.h"
#include "mhtable.h"

extern int nfound;
extern int nexafound;
extern int nprefound;

#define NUM_CHAR 30
#define PATFILE "pattern.txt"
#define TEXTFILE "text.txt"


int main()
{

	char str[1024][30];
	static char url[200];
	COMPONENT *harray[NUMHASH];//建立一个NUMHASH个哈希表的指针数组
	memset(harray,0,NUMHASH*sizeof(COMPONENT*));

	FILE *fp, *proc;
	pid_t pid;
	long tmp;
	int i;
	struct timeval starttv,endtv;
	unsigned long uLong;
        unsigned long long uLLong;
	unsigned int j;
        unsigned long vsize;

	nfound =0;
	nexafound =0;
	nprefound =0;

	char PatternFileName[NUM_CHAR];
	char TextFileName[NUM_CHAR];
	memset(PatternFileName, '\0',NUM_CHAR);
	memset(TextFileName, '\0',NUM_CHAR);
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

        if(gettimeofday(&starttv, NULL) < 0)
        {
        	fprintf(stderr, "%s:%d\tgettimeofday error\n", __FILE__, __LINE__);
        	exit(0);
        }
       int k=0;
        while(fscanf(fp,"%s",url)==1)
        {
		k++;
		urlparse(str,url);
//		printf("%d\n",k);
		hcompt_harray_build(harray,str);
        }
        fclose(fp);

        if(gettimeofday(&endtv, NULL) < 0)
        {
        	fprintf(stderr, "%s:%d\tgettimeofday error\n", __FILE__, __LINE__);
		exit(0);
	}
	printf("Init tasks %ld ms\n", endtv.tv_sec * 1000 + endtv.tv_usec / 1000 - starttv.tv_sec * 1000 - starttv.tv_usec / 1000);

/***************TEST*********************************************/
/*	for(i=0;i<30;i++)
	{
		if(*str[i] != '\0')
			 printf("str[%d]=%s\n",i,str[i]);
	}*/
/****************TEST********************************************/

//	test_harray(harray);

/************************计算内存********************************/
/*	pid = getpid();
	sprintf(url, "/proc/%d/stat", pid);
	proc = fopen(url, "r");
	if(proc == NULL)
	{
		fprintf(stderr, "get stat error\n");
		exit(0);
	}
	i = fscanf(proc, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %d", &pid, url, &url[0], &pid, &pid, &pid, &pid, &pid, &j, &uLong, &uLong, &uLong,&uLong, &uLong,&uLong, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp, &uLLong, &vsize, &tmp, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &uLong, &pid, &pid, &j, &j, &uLLong, &uLong, &pid);


	fclose(proc);
	printf("The memory used is %ld MB\n", (vsize / 1024 / 1024));
*/
/*****************************************************************************/

	fp = fopen(TextFileName, "r");
	if(fp == NULL)
	{
		fprintf(stderr, "open %s failed\n", PatternFileName);
		exit(0);
	}

	if(gettimeofday(&starttv, NULL) < 0)
	{
		fprintf(stderr, "%s:%d\tgettimeofday error\n", __FILE__, __LINE__);
		exit(0);
	}

	while(fscanf(fp,"%s",url)==1)
	{
		urlparse(str,url);
/***************TEST*********************************************/
/*for(i=0;i<30;i++)
{
	if(*str[i] != '\0')
		 printf("str[%d]=%s\n",i,str[i]);
}*/
/****************TEST********************************************/

		url_search(harray,str);
	}
	fclose(fp);

	if(gettimeofday(&endtv, NULL) < 0)
	{
		fprintf(stderr, "%s:%d\tgettimeofday error\n", __FILE__, __LINE__);
		exit(0);
	}
	printf("Search tasks %ld ms\n", endtv.tv_sec * 1000 + endtv.tv_usec / 1000 - starttv.tv_sec * 1000 - starttv.tv_usec / 1000);
	printf("The num of  exactmatch=%d\n",nexafound);
	printf("The num of prefixmatch=%d\n",nprefound);
	printf("The num of       match=%d\n",nfound);


	hcompt_harray_destroy(harray);

	return 0;
}
