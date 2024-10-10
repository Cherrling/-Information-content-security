/*****************************************************************
*author:     xudongliang
*copyright:  www.pact518.hit.edu.cn
*date:       2014.01.02
*
*****************************************************************/
#include <stdbool.h>
#include "mhtable.h"
#include "hash.h"

int nfound;//总匹配的个数
int nexafound;//精确匹配的个数
int nprefound;//只匹配到前缀的个数


/**************************************************************
 *函数：COMPONENT * hcompt_array_new()
 *目的：创建一个ＵＲＬ组件的哈希数组
 *参数：无
 *返回：struct _component_struct_ *类型的哈希数组指针
 * ***********************************************************/
COMPONENT *hcompt_array_new()
{
	COMPONENT *hcompt_array = (COMPONENT *)malloc(HASHTABLESIZE*sizeof(COMPONENT));
	if(!hcompt_array) return 0;

	memset(hcompt_array,0,HASHTABLESIZE*sizeof(COMPONENT));

	return hcompt_array;
}


/**************************************************************
 *函数：int hcompt_array_build(COMPONENT **harray, char str[][30])
 *目的：构建ＵＲＬ组件的哈希链表
 *参数：h_array -> COMPONENT类型的哈希数组
	char **str -> URL组件数组
 *返回：success->1
	failed-> 0
 * ***********************************************************/
int hcompt_harray_build(COMPONENT **harray, char str[][30])
{
	unsigned int i=0;
	unsigned int j=0;
	unsigned int index; //哈希索引
	COMPONENT *ctem1,*ctem2;
	HNEXTCOMPONENT *htem0,*htem1;
	unsigned int hvalue[NUMHASH];
	memset(hvalue,0,NUMHASH);


	for(i=0;*str[i] != '\0';i++)
	{
		if(i>30)
		{
			printf("--!--The num of harray is less than i!\n");
			exit(0);
		}
		if(harray[i] == NULL)
		{
			harray[i] =hcompt_array_new();
		}

		hvalue[i] = index = HASH(str[i]) % HASHTABLESIZE;
		if(harray[i][index].str == NULL)
		{
			harray[i][index].str = (char*)malloc(sizeof(str[i]));
			if(!harray[i][index].str) return 0;
			memcpy(harray[i][index].str,str[i],sizeof(str[i]));
//			printf("--B--%d %d %s\n",i,index,harray[i][index].str);
		}
		else
		{
			ctem2=harray[i][index].next;
			while(ctem2 != NULL && strcmp(ctem2->str,str[i])!=0)
			{
				ctem2=ctem2->next;
			}
			if(strcmp(harray[i][index].str,str[i])!=0 && ctem2 ==NULL)//新来的元素确定不存在
			{
				ctem1 = (COMPONENT *)malloc(sizeof(COMPONENT));
				if(!ctem1) return 0;
				memset(ctem1,0,sizeof(COMPONENT));
				ctem1->str =  (char*)malloc(sizeof(str[i]));
				if(!ctem1->str) return 0;
				memcpy(ctem1->str,str[i],sizeof(str[i]));

				ctem2=harray[i][index].next;
				harray[i][index].next = ctem1;
				ctem1->next = ctem2;
//				printf("--B--%d %d %s\n",i,index,ctem1->str);

			}
		}
		if(i > 0)//为二层以后的哈希表添加后缀
		{
			htem0=(HNEXTCOMPONENT *)malloc(sizeof(HNEXTCOMPONENT));
			if(!htem0) return 0;
			memset(htem0,0,sizeof(HNEXTCOMPONENT));
			htem0->hash = index;

			j=hvalue[i-1];
			ctem2 = harray[i-1][j].next;
			while(ctem2 != NULL && strcmp(str[i-1],ctem2->str) != 0)
			{
				ctem2=ctem2->next;
			}
			if(ctem2 == NULL)//说明与第一个元素相同,即strcmp(harray[i-1][j].str,str[i-1] == 0)
			{
				if(harray[i-1][j].hnext_compt == NULL)
				{
					harray[i-1][j].hnext_compt = htem0;
				}
				else
				{
					htem1=harray[i-1][j].hnext_compt;
					harray[i-1][j].hnext_compt=htem0;
					htem0->next= htem1;
				}

			}
			else
			{
				if(ctem2->hnext_compt == NULL)
				{
					ctem2->hnext_compt = htem0;
				}
				else
				{
					htem1=ctem2->hnext_compt;
					ctem2->hnext_compt = htem0;
					htem0->next = htem1;

				}

			}
		}
	}
	return 1;
}
/**************************************************************
*函数：int url_search(COMPONENT **harray, char str[][30])
*目的：匹配ＵＲＬ组件，找到最长前缀
*参数：h_array -> COMPONENT类型的哈希数组
       char **str -> URL组件数组
*返回：nfound->匹配到的个数
* ***********************************************************/
int url_search(COMPONENT **harray, char str[][30])
{
	int i=0;
	bool b=true;
	bool b2=false;
	unsigned int index; //哈希索引
	COMPONENT *ctem1;
	HNEXTCOMPONENT *htem1;
	unsigned int hvalue[NUMHASH];
	memset(hvalue,0,NUMHASH);


	for(i=0;*str[i]!='\0' && b==true;i++)
	{
		hvalue[i]=index=HASH(str[i]) % HASHTABLESIZE;
		if(i==0)
		{
			if(harray[i][index].str != NULL)
			{
				if(strcmp(harray[i][index].str,str[i]) !=0)
				{
					ctem1=harray[i][index].next;
					while(ctem1!=NULL && strcmp(ctem1->str,str[i])!=0)
					{
						ctem1 = ctem1->next;
					}
					if(ctem1 == NULL)
					{
						b=false;//结束匹配
					}

				}
				else
					b2=true;//至少匹配了第一个组件
			}
			else
				b=false;//结束匹配
		}
		else
		{
			ctem1=harray[i-1][hvalue[i-1]].next;
			while(ctem1 != NULL && strcmp(ctem1->str,str[i-1])!=0)
			{
				ctem1 = ctem1->next;
			}
			if(ctem1 == NULL)//说明哈希数组中的第一个元素匹配上了 strcmp(harray[i-1][hvalue[i-1]].str,str[i-1])==0
				htem1=harray[i-1][hvalue[i-1]].hnext_compt;
			else//找到匹配的那个元素 strcmp(ctem1->str,str[i-1])==0
				htem1=ctem1->hnext_compt;

			while(htem1!=NULL && htem1->hash != index)
			{
				htem1=htem1->next;
			}
			if(htem1 == NULL)
			{
				b=false;
			}
			else
			{
				if(harray[i][index].str != NULL)
				{
					if(strcmp(harray[i][index].str,str[i]) !=0)
					{
						ctem1=harray[i][index].next;
						while(ctem1!=NULL && strcmp(ctem1->str,str[i])!=0)
						{
							ctem1 = ctem1->next;
						}
						if(ctem1 == NULL)
						{
							nfound++;
							nprefound++;
//							printf("--Match%d--The %dth Longest Prefix1 is %d\n",nfound,nprefound,i);
							b=false;//结束匹配
							b2=false;
						}
					}
				}
				else//实验中这种情况没出现过，why?因为前一个哈希表中已经验证过在本哈希表中该元素是有值的，可能是冲突的值，但一定是有值的。
				{
					nfound++;
					nprefound++;
//					printf("--Match%d--The %dth Longest Prefix2 is %d\n",nfound,nprefound,i);
					b=false;//结束匹配
				}
			}
		}
	}
	if(b==true && *str[i]=='\0')
	{
		nfound++;
		nexafound++;
//		printf("--ExactMatch%d--The %dth longth of URL is %d \t %s\n",nfound,nexafound,i,str[i-1]);
	}
	else if(b2==true)// && *str[i]!='\0' )
	{
		nfound++;
		nprefound++;
//		printf("--Match%d--The %dth Longest Prefix3 is %d\n",nfound,nprefound,i-1);
	}


	return nfound;
}

/**************************************************************
*函数：void  hcompt_array_destroy()
*目的：释放ＵＲＬ组件的哈希链表
*参数：harray -> COMPONENT类型的哈希数组
*返回：void
* ************************************************************/
void hcompt_harray_destroy(COMPONENT **harray)
{
	int i;
	int j;
	COMPONENT *ctem1,*ctem2;
	HNEXTCOMPONENT *htem1,*htem2;

	for(i=0;harray[i] != 0;i++)
	{
		for(j=0;j<HASHTABLESIZE;j++)
		{
			if(harray[i][j].str != NULL)
			{
				free(harray[i][j].str);
				if(harray[i][j].hnext_compt != NULL)
				{
					htem1=htem2=harray[i][j].hnext_compt->next;
					while(htem1 != NULL)
					{
						htem2=htem2->next;
						free(htem1);
						htem1=htem2;
					}
					free(harray[i][j].hnext_compt);
				}

				if(harray[i][j].next != NULL)
				{
					ctem1=ctem2 = harray[i][j].next;
					while(ctem1 != NULL)
					{
						ctem2 = ctem2->next;

						free(ctem1->str);
						htem1=htem2=ctem1->hnext_compt;
						while(htem1 != NULL)
						{
							htem2=htem2->next;
							free(htem1);
							htem1=htem2;
						}
						free(ctem1);
						ctem1 = ctem2;
					}
					free(harray[i][j].hnext_compt);
				}

			}
		}
	}
}





/**************************************************************
*函数：void * test_harray(COMPONENT **harray)
*目的：测试ＵＲＬ组件的哈希链表
*参数：none
*返回：void
* ***********************************************************/
void test_harray(COMPONENT **harray)
{
	int i;
	int j;
	COMPONENT *ctem1,*ctem2;
	HNEXTCOMPONENT *htem1,*htem2;

	for(i=0;i<NUMHASH;i++)
	{
		if(harray[i] != NULL)
		{
			for(j=0;j<HASHTABLESIZE;j++)
			{
				if(harray[i][j].str !=NULL)
				{
					ctem1=ctem2=harray[i][j].next;
					htem1=htem2=harray[i][j].hnext_compt;
					printf("--T1--%d  %d %s\t",i,j,harray[i][j].str);
					while(htem1!= NULL)
					{
						printf("h1 %d\t",htem1->hash);
						htem1 = htem1->next;
					}
					printf("\n");

					while(ctem1 != NULL)
					{
						printf("--T2--%d  %d  %s\t",i,j,ctem1->str);

						htem1=ctem1->hnext_compt;
						while(htem1 != NULL)
						{
							printf("h2 %d\t",htem1->hash);
							htem1=htem1->next;
						}
						ctem1=ctem1->next;
						printf("\n");
					}

				}
			}
		}
	}

}


