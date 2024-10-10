/*****************************************************************
 *文件作用：各种测试函数
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2012.05.11
 *****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rfpwm.h"

/***************************************************************
 *函数：void test_load_pattern_to_list(RFPWM_STRUCT *rfpwm)
 *目的：测试模式串是否准确加载到链表结构中
 *参数：RFPWM_STRUCT *rfpwm => 模式集结构体 
 *返回值：无
 **************************************************************/
void test_load_pattern_to_list(RFPWM_STRUCT *rfpwm)
{
	int i;	
	RFPWM_PATTERN_STRUCT *pl;
	if(rfpwm->patlist)
	{
		i =3700;
		for(pl=rfpwm->patlist;pl!=NULL&&i<4000;pl=pl->next)
		{
			i++;
			printf("%d %s len=%d\n",i,pl->pat,pl->len);
		}
	}
}

/***************************************************************
 *函数：void test_load_pattern_to_array(RFPWM_STRUCT *rfpwm)
 *目的：测试模式串是否准确加载到模式数组中
 *参数：RFPWM_STRUCT *rfpwm => 模式集结构体 
 *返回值：无
 **************************************************************/
void test_load_pattern_to_array(RFPWM_STRUCT*rfpwm)
{
	int i;	
	//测试数组中加载的模式串是否正确
	if(rfpwm->patarray)
	{
//		for(i=0;i<rfpwm->numpat;i++)
		for(i=0;i<100&&i<rfpwm->numpat;i++)
		{
			printf("%d %d %s %d\n",i,rfpwm->patarray[i].index,rfpwm->patarray[i].pat,rfpwm->patarray[i].fingerprint);
		}
	}	
}


/***************************************************************
 *函数：void test_pattern_fingerprint(RFPWM_STRUCT *rfpwm)
 *目的：测试是否得出每个模式串的唯一指纹
 *参数：RFPWM_STRUCT *rfpwm => 模式集结构体 
 *返回值：无
 **************************************************************/
void test_pattern_fingerprint(RFPWM_STRUCT *rfpwm)
{
	
	int i;	
	RFPWM_PATTERN_STRUCT *pl;
	//测试是否得出每个模式串的唯一指纹	
	if(rfpwm->patlist)
	{
		i=0;
		for(pl=rfpwm->patlist;pl!=NULL&&i<200;pl=pl->next)
		{
			i++;
			printf("index=%d patlen=%d uniquefingerprint=%d frequency=%d\n",pl->index,pl->len,pl->fparray[pl->index].fingerprint,pl->fparray[pl->index].frequency);
		}	
	}	
}
