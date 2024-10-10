/*****************************************************************
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2012.05.11
 *
 *****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "hash.h"
#include "rfpwm.h"

int nfound=0;
u_int32_t SMALLEST;
int NOCASE; //是否区分大小写，0－不区分，1－区分,默认区分大小写

/*64KB Memory*/
static unsigned char Tc[64*1024];
/*
** Case Translation Table
*/
//static unsigned char xlatcase[256];

/*
* Init the xlatcase Table,Trans alpha to UpperMode
* Just for the NoCase State
*/
/*
static void init_xlatcase ()
{
	int i;
	for (i = 0; i < 256; i++)
	{
		xlatcase[i] = toupper (i);
	}
}
*/

/*
*Convert the pattern string into upper
*/
static void ConvertCaseEx (unsigned char *d, unsigned char *s, int m)
{
	int i;
	for (i = 0; i < m; i++)
	{
//		d[i] = xlatcase[s[i]];
		d[i] = toupper(s[i]);
	}
}

/******************************************
 *函数：RFPWM_STRUCT *rfpWM_New()
 *目的：创建一个模式集结构
 *参数：无
 *返回值：RFPWM_STRUCT *p
 ******************************************/
RFPWM_STRUCT *rfpwm_new()
{
	RFPWM_STRUCT *p=(RFPWM_STRUCT *)malloc(sizeof(RFPWM_STRUCT));
	if(!p)return 0;
	memset(p,0,sizeof(RFPWM_STRUCT));
	p->smallest = 100000;
	return p;
}

/******************************************
 *函数：void rfpWM_Pattern_Struct_free(RFPWM_PATTERN_STRUCT*)
 *目的：释放模式集结构
 *参数：RFPWM__PATTERN_STRUCT *pl,模式串链表
 *返回值：无
 ******************************************/
void rfpwm_pattern_struct_free(RFPWM_PATTERN_STRUCT *pl)
{

	if(pl)
	{
		for(;pl!=NULL;pl=pl->next)//该结构中的pat不释放，patarray结构中要用
		{
			if(pl->fparray) free(pl->fparray);
		}
		free(pl);
	}
}
/******************************************
 *函数：void rfpWMfree(RFPWM_STRUCT*)
 *目的：释放模式集结构
 *参数：RFPWM_STRUCT *p,模式串集
 *返回值：无
 ******************************************/
void rfpwmfree(RFPWM_STRUCT *p)//释放空间函数,使用了内存池管理后，该函数就不用了
{
	if(p->patarray)
	{
		int32_t i;
		for(i=0;i<p->numpat;i++)
		{
			if(p->patarray[i].pat) free(p->patarray[i].pat);
		}
		free(p->patarray);
	}
	if(p->numarray) free(p->numarray);
	if(p->hash) free(p->hash);
	if(p->shift) free(p->shift);
	if(p->fingerprint) free(p->fingerprint);
	free(p);
}

/******************************************
 *函数：int rfpWMaddpat(RFPWM_STRUCT*,unsigned char,u_int32_t)
 *目的：向模式集结构RFPWM_PATTERN_STRUCT中添加一个模式串
 *参数：rpat=>模式链表，将文本文件中的模式串读入到该结构中
	pat => 模式串，将该模式串存入patlist中
	len => 模式串的长度
 *返回值：成功返回0，否则 －1
 ******************************************/
int rfpwmaddpat(RFPWM_STRUCT *p, unsigned char *pat,u_int32_t len)
{
	RFPWM_PATTERN_STRUCT *rpat;
	//由于RFPWM_PATTERN_STRUCT结构只是临时存储结构，所以不在内存池中申请空间
	rpat = (RFPWM_PATTERN_STRUCT *)malloc(sizeof(RFPWM_PATTERN_STRUCT));
	if(!rpat)return -1;
	//由于该结构中的模式串在RFPWM_PATARRAY_STRUCT结构中用到，所以在内存池中申请
	rpat->pat = (unsigned char*)malloc(len+1);
	if(!(rpat->pat))return -1;
	memset(rpat->pat+len,0,1);
	if(NOCASE == 0)//不区分大小写,进行大小写转换
	{
		ConvertCaseEx(rpat->pat,pat,len);
	}
	else //区分大小写
		memcpy(rpat->pat,pat,len);

	rpat->len = len;
	p->numpat++;

	if(len<p->smallest) p->smallest = len;
	rpat->next =p->patlist;
	p->patlist = rpat;

	return 0;
}

/******************************************
 *函数：int winfingerprint(RFPWM_STRUCT*)
 *目的：计算出每个模式串中的每个窗口的指纹,并得出每个模式串的唯一指纹
 *参数：RFPWM_STRUCT *p => 模式串集的结构体
 *返回值：成功返回0，否则 －1
 ******************************************/
int winfingerprint(RFPWM_STRUCT *p)
{
	int32_t i,j;
	int32_t minindex=0;//最小索引值
	int32_t minfrequency;//指纹出现的最小频率
	int32_t winlen;//窗口长度，就是最短模式串的长度
	int32_t winnum;//窗口的数量，就是一个模式串有多少个指纹
	unsigned char *ps;
	FINGER_PRINT *fparray;
	RFPWM_PATTERN_STRUCT *patlist,*pl;

	patlist = p->patlist;
	winlen = p->smallest;//最短模式串的长度就是窗口的长度

	//计算每个模式串的每个窗口的指纹
	for(patlist=p->patlist;patlist!=NULL;patlist=patlist->next)
	{
		winnum = patlist->len - winlen + 1;
		fparray= (FINGER_PRINT *)malloc(winnum*sizeof(FINGER_PRINT));
		if(!fparray) return -1;
		memset(fparray,0,winnum*sizeof(FINGER_PRINT));
		patlist->fparray = fparray;

		ps = patlist->pat;
		for(i=0;i<winnum;i++)
		{
			patlist->fparray[i].fingerprint=FingerPrint(ps++,winlen);//计算每个窗口的指纹
//			printf("%d fingerprint=%u  ",i,patlist->fparray[i].fingerprint);
		}
//		printf("\n");
	}
	//统计每个模式串的每个窗口指纹出现的频率
	for(patlist=p->patlist;patlist!=NULL;patlist=patlist->next)
	{
		winnum = patlist->len - winlen + 1;
		for(i=0;i<winnum;i++)
		{

			for(pl=p->patlist;pl!=NULL;pl=pl->next)
			{
				for(j=0;j<winnum;j++)
				{
					if(patlist->fparray[i].fingerprint==pl->fparray[j].fingerprint)
						patlist->fparray[i].frequency++;

				}
			}

		}
	}

	//查找每个模式串的唯一指纹，就是说找这个模式串中哪一个窗口的指纹出现的次数最少，以它作为该模式串的指纹
	for(pl=p->patlist;pl!=NULL;pl=pl->next)
	{
		winnum = pl->len - winlen + 1;
		minfrequency=100000;
		for(i=0;i<winnum;i++)
		{
			if(minfrequency > pl->fparray[i].frequency)
			{
				minindex = i;
				minfrequency = pl->fparray[i].frequency;
			}
		}
		pl->index = minindex;//将出现频率最小的窗口索引赋给模式串唯一指纹索引
	}
	return 0;
}

/************************************************************
 *函数：void sort(RFPWM_STRUCT *)
 *目的：对所有模式串，按窗口最后两个字符的哈希值从小到大排序
 *参数：RFPWM_STRUCT *p => 模式串集的结构体
 *返回值：无
 * *********************************************************/
void sort(RFPWM_STRUCT *p)
{
	u_int32_t winlen=p->smallest;//窗口长度
	int i,j,flag;//冒泡排序标志位。当一趟比较无交换时，说明已经完成排序
	struct rfpwm_patarray_struct *pt1,*pt2,pt_temp;
	HASH_TYPE h_temp1,h_temp2;
	//冒泡排序
	for(i=p->numpat-1,flag=1;i>0&&flag;i--)
	{
		flag=0;
		for(j=0;j<i;j++)
		{
			pt1=&(p->patarray[j]);
			pt2=&(p->patarray[j+1]);
			h_temp2 = HASH16(&(pt2->pat[pt2->index+winlen-2]));
			h_temp1 = HASH16(&(pt1->pat[pt1->index+winlen-2]));
			if(h_temp2<h_temp1)//比较每个字符串截取部分最后两个字符的哈希值
			{
				flag=1;
				memcpy(&pt_temp,pt2,sizeof(RFPWM_PATARRAY_STRUCT));
				memcpy(pt2,pt1,sizeof(RFPWM_PATARRAY_STRUCT));
				memcpy(pt1,&pt_temp,sizeof(RFPWM_PATARRAY_STRUCT));
			}
		}
	}
}
/************************************************************
 *函数：int compare(const void *a,const void *b)
 *目的：qsort中的比较函数，比较两个元素之间的大小
 *参数：
 *返回值:
 * *********************************************************/
int compare(const void *a, const void *b)
{
	HASH_TYPE h_temp1,h_temp2;
	RFPWM_PATARRAY_STRUCT *pt1= (RFPWM_PATARRAY_STRUCT *)a;
	RFPWM_PATARRAY_STRUCT *pt2= (RFPWM_PATARRAY_STRUCT *)b;
	h_temp2 = HASH16(&(pt2->pat[pt2->index+SMALLEST-2]));
	h_temp1 = HASH16(&(pt1->pat[pt1->index+SMALLEST-2]));
	return h_temp2-h_temp1;
}
/* ****************************************************************
函数：static void rfpwmhashtable(RFPWM_STRUCT *)
目的：计算共有多少个不同的哈希值，且从小到大
参数：ps => 模式串集
返回：
****************************************************************/
static void rfpwmhashtable(RFPWM_STRUCT *p)
{
	int i;
	HASH_TYPE hindex,sindex,snum;
	int32_t winindex;//每个模式串的窗口索引
	u_int32_t winlen=p->smallest;
	RFPWM_PATARRAY_STRUCT *pt;
	pt=p->patarray;

	p->hash=(HASH_TYPE*)malloc(sizeof(HASH_TYPE)*HASHTABLESIZE);//HASH表
	if(!p->hash)
	{
		fprintf(stderr,"HASH table malloc error @ %s:%d\n",__FILE__,__LINE__);
		return;
	}
	for(i=0;i<HASHTABLESIZE;i++)
	{
		p->hash[i]=(HASH_TYPE)-1;
	}
	for(i=0;i<p->numpat;i++)
	{
		winindex=pt[i].index;
		hindex = HASH16(&(pt[i].pat[winindex+winlen-2]));
		sindex=p->hash[hindex]=i;
		snum=1;
		//此时哈希表已经有序了
		while((++i<p->numpat)&&hindex==HASH16(&(pt[i].pat[pt[i].index+winlen-2])))//找后缀相同的子串数
			snum++;
		p->numarray[sindex]=snum;//第i模式串，其后的模式串与其后缀相同的子串的个数
		i--;
	}
}

/* ****************************************************************
    函数：static void rfpwmshifttable(RFPWM_STRUCT *p)
	目的：建立shift表，算出每个字符块要移动的距离
	参数：
		p => 模式串集
    返回：

 ****************************************************************/
static void rfpwmshifttable(RFPWM_STRUCT *p)
{
	int i,k;
	u_int32_t winlen=p->smallest;//窗口长度
	HASH_TYPE shift,cindex;
	RFPWM_PATARRAY_STRUCT *pt;

	p->shift=(HASH_TYPE *)malloc(SHIFTTABLESIZE*sizeof(HASH_TYPE));
	if(!p->shift) return;

	for(i=0;i<SHIFTTABLESIZE;i++)
	{
		p->shift[i]=(HASH_TYPE)(winlen-2+1);//初始化shift表，初始值为最短字符串的长度
	}

	for(i=0;i<p->numpat;i++)
	{
		pt=p->patarray;
		for(k=0;k<winlen-1;k++)
		{
			shift = (HASH_TYPE)(winlen-2-k);
			cindex=HASH16(&(pt[i].pat[pt[i].index+k]));
			if(shift<p->shift[cindex])
				p->shift[cindex]=shift;
		}
	}
}


/* ****************************************************************
    函数：static void rfpwmfingerprinttable(RFPWM_STRUCT *p)
	目的：建立Prefix表
	参数：
		p => 模式串集
    返回：
	    无
 ****************************************************************/
//static void rfpwmfingerprinttable(RFPWM_STRUCT *p){}

/* ****************************************************************
函数：int rfpwmfingerprintmatch(RFPWM_STRUCT *,int ,unsigned char *,unsigned char *)
	目的：后缀哈希值相同，比较前缀以及整个字符串匹配
	参数：
		p => 模式串集
		lindex =>lindex为后缀哈希值相同的那些模式子串中的一个模式子串的index
		Tx => 要进行匹配的字符串序列
		T => 模式子串
    返回：
	    无
 ****************************************************************/
int rfpwmfingerprintmatch(RFPWM_STRUCT *p,int lindex ,
			unsigned char *Tx,unsigned char *T)
{
//	int nfound=0;
	int len;
	u_int32_t tfingerprint;//截取文本块的指纹
	u_int32_t winlen=p->smallest;
	unsigned char *pat;
	unsigned char *tx;
	RFPWM_PATARRAY_STRUCT *pt,*ptend;

	pt=&p->patarray[lindex];
	ptend=pt+p->numarray[lindex];

	tfingerprint=FingerPrint(T,winlen);//取得文本块的指纹

	for(;pt<ptend;pt++)
	{
		if(pt->fingerprint!=tfingerprint)
			continue;
		else//如果指纹相同，则
		{
			pat=pt->pat;
			len=pt->len;
			tx=T-(pt->index);//窗口指纹并不是在模式串的第一个字符开始的
			if(strncmp((const char*)pat,(const char*)tx,len)==0)
			{
				nfound++;
			}
			//while(*(pat++)==*(tx++)&&(len--)!=0);
			//if(len==0)//匹配成功
			//{
			//	nfound++;
			//}
			//while(*(pat++)==*(tx++)&&*(pat-1)!='\0');
			//if(*(pat-1)=='\0')//匹配成功
			//{
			//	nfound++;
			//}
		}
	}
	return 0;
}

/* ****************************************************************
    函数：int rfpwmsearch(RFPWM_STRUCT *p,unsigned char *Tx,int n)
	目的：字符串匹配查找
	参数：
		p => 模式串集
		Tx => 被查找的字符串序列
		n => 被查找的字符串长度
    返回：nfound,匹配到的个数
 ****************************************************************/
int rfpwmsearch(RFPWM_STRUCT *p,unsigned char *Tx,int n)
{
	//int nfound=0;
	int Tleft,lindex,tshift;
	HASH_TYPE hindex;
	//T指向窗口的第一个字符
	unsigned char *T,*Tend,*window;//window指向窗口的最后一个字符
	if(n<p->smallest)//被查找的字符串比最小的模式串还短
		return -1;
	if(NOCASE == 0)//不区分大小写
	{
		/* Case conversion */
		ConvertCaseEx (Tc, Tx, n);
		Tend=Tc+n;
		window=Tc+p->smallest-1;
		T=Tc;
	}
	else
	{
		Tend=Tx+n;
		window=Tx+p->smallest-1;
		T=Tx;
	}
	Tleft=n;
	for(;window<Tend;T++,window++,Tleft--)
	{
		hindex=HASH16(window-1);
		tshift=	p->shift[hindex];
		while(tshift)
		{
			window+=tshift;
			T+=tshift;
			Tleft-=tshift;
			if(window>Tend) return 0;
			tshift=p->shift[HASH16(window-1)];
		}
		//tshift=0,表明后缀哈希值已经相同
		if((lindex=p->hash[HASH16(window-1)])==(HASH_TYPE)-1)
			continue;
		lindex=p->hash[HASH16(window-1)];
		rfpwmfingerprintmatch(p,lindex,Tx,T);
	}
//	return nfound;
	return 0;
}


/******************************************
 *函数：int rfpWMPrecpat(RFPWM_STRUCT*)
 *目的：计算出每个模式串中的每个窗口的指纹,并得出每个模式串的唯一指纹
 *参数：RFPWM_STRUCT *p => 模式串集的结构体
 *返回值：成功返回0，否则 －1
 ******************************************/
int rfpwmprecpat(RFPWM_STRUCT *p)
{
	int i;
	RFPWM_PATTERN_STRUCT *pl;
	RFPWM_PATARRAY_STRUCT *pt;
	pl=p->patlist;
	SMALLEST=p->smallest;
	p->patarray=(RFPWM_PATARRAY_STRUCT *)malloc(sizeof(RFPWM_PATARRAY_STRUCT)*p->numpat);
	if(!p->patarray) return -1;

	p->numarray=(HASH_TYPE*)malloc(sizeof(HASH_TYPE)*p->numpat);
	if(!p->numarray) return -1;
	memset(p->numarray,0,sizeof(HASH_TYPE)*p->numpat);

	pt=p->patarray;
	for(i=0;pl!=NULL&&i<p->numpat;pl=pl->next,i++)
	{
		pt[i].pat=pl->pat;
		pt[i].index=pl->index;
		pt[i].fingerprint=pl->fparray[pl->index].fingerprint;
		pt[i].len=pl->len;
	}
	rfpwm_pattern_struct_free(pl);//释放RFPWM_PATTERN_STRUCT结构
	//sort是冒泡排序，qsort是快速排序，qsort的速度要快一些
	sort(p);
//	qsort(p->patarray,p->numpat,sizeof(RFPWM_PATARRAY_STRUCT),compare);
	rfpwmhashtable(p);
	rfpwmshifttable(p);

	return 0;
}


