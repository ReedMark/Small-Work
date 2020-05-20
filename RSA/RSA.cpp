/*
* @Author: Reed Mark
* @Date:   2020-05-18 16:23:26
* @Last Modified by:   Reed Mark
* @Last Modified time: 2020-05-20 19:39:32
*/
#include "pch.h"
#define _AFXDLL
#define bool int
#define true 1
#define false 0
#include "RSA.h"
/* 保存私钥d*/
struct pKeySet
{
	unsigned int set[MAX_NUM];
	unsigned int size;
}pset;
/*保存公私钥*/
struct pPairKey
{
	unsigned int d;
	unsigned int e;
	unsigned int n;
}pairkey;
/*判断两个数是否互质*/
bool isPrime(unsigned int m, unsigned int n)
{
	unsigned int i = 0;
	bool Flag = true;
	if (m < 2 || n < 2) return false;
	unsigned int tem = (m > n) ? n : m;
	for (i = 2; i <= tem && Flag; i++)
	{
		bool mFlag = true;
		bool nFlag = true;
		if (m % i == 0) mFlag = false;
		if (n % i == 0) nFlag = false;
		if (!mFlag && !nFlag) Flag = false;
	}
	if (Flag) return true;
	else return false;
}
/*由素数PQ生成私钥d*/
unsigned int MakePrivateKey(unsigned int uiP, unsigned int uiQ)
{
	unsigned int i = 0;
	unsigned int z = (uiP - 1) * (uiQ - 1);
	pset.size = 0;
	for (i = 0; i < z; i++)
	{
		if (isPrime(i, z)) pset.set[pset.size++] = i;
	}
	return pset.size;
}
/*生成RSA公、私钥对*/
unsigned int MakePairkey(unsigned int uiP, unsigned int uiQ, unsigned int uiD)
{
	bool bFlag = true;
	unsigned int i = 0;
	unsigned int e;
	unsigned int z = (uiP - 1) * (uiQ - 1);
	unsigned int d = pset.set[uiD];
	if (!isPrime(z, d)) return ERROR_NOEACHPRIME;
	for (i = 2; i < z; i++)
	{
		if ((i * d) % z == 1)
		{
			e = i;
			bFlag = false;
		}
	}
	if (bFlag) return ERROR_NOPUBLICKEY;
	if ((d * e) % z == 1)
	{
		ERROR_GENERROR;
		pairkey.d = d;
		pairkey.e = e;
		pairkey.n = uiP * uiQ;
		return OK;
	}
}
/*对外提供接口，获得公私密钥*/
unsigned int GetPairKey(unsigned int &d, unsigned int &e)
{
	d = pairkey.d;
	e = pairkey.e;
	return pairkey.n;
}
/*对外提供接口，由用户选择ID得到私钥d*/
unsigned int GetPrivateKey(unsigned int iWhich)
{
	if (pset.size >= iWhich) return pset.set[iWhich];
	else return 0;
}
/*RSA加密运算
  n: 公钥n
  e: 公钥e
  mw: 加密明文
  mLength: 明文长度
  cw: 密文输出*/
void RasEncrypt(int n, int e, char* mw, int mLength, int*&cw)
{
	int i = 0, j = 0;
	__int64 temInt = 0;
	for (i = 0; i < mLength; i++)
	{
		temInt = mw[i];
		if (e != 0)
		{
			for (j = 1; j < e; j++)
			{
				temInt = (temInt * mw[i]) % n;
			}
		}
		else
		{
			temInt = 1;
		}
		cw[i] = (int)temInt;
	}
}
/*RSA解密运算*/
void RsaDecrypt(int n, int d, int*&cw, int cLength, char *mw)
{
	int i = 0, j = -1;
	__int64 temInt = 0;
	for (i = 0; i < cLength / 4; i++)
	{
		mw[i] = 0;
		temInt = cw[i];
		if (d != 0)
		{
			for (j = 1; j < d; j++)
			{
				temInt = (__int64)(temInt * cw[i]) % n;
			}
		}
		else
		{
			temInt = 1;
		}
		mw[i] = (char)temInt;
	}
}
void OutputKey()
{
	printf("PublicKey(e,n):(%d, %d)\n", pairkey.e, pairkey.n);
	printf("PrivateKey(d,n):(%d, %d)\n", pairkey.d, pairkey.n);
}

