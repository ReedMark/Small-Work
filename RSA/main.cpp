/*
* @Author: Reed Mark
* @Date:   2020-05-20 18:03:39
* @Last Modified by:   Reed Mark
* @Last Modified time: 2020-05-20 19:39:33
*/
#include "pch.h"
#include "RSA.h"
#include <stdio.h>
#include <math.h>
#include <afxwin.h>
#define DECRYPT_FILE "RSA加密密文.txt"
#define ENCRYPT_FILE "RSA解密明文.txt"
#define MAX_FILE 1024 * 1024 * 2
void Usage(const char* appname)
{
	printf("\n\tusage.rsa -k 素数P 素数Q\n");
	printf("\tusage rsa -e 明文文件 公钥e 公钥n\n");
	printf("\tusage rsa -d 密文文件 私钥d 私钥n\n");
}
bool isNumber(const char* strNumber)
{
	unsigned int i;
	if (!strNumber) return false;
	for (i = 0; i < strlen(strNumber); i++)
	{
		if (strNumber[i] < '0' || strNumber[i] > '9')
		{
			return false;
		}
	}
	return true;
}
bool isPrimeNumber(unsigned int num)
{
	unsigned int i;
	if (num <= 1) return false;
	unsigned int sqr = (unsigned int)sqrt((double)num);
	for (i = 2; i <= sqr; i++)
	{
		if (num % i == 0) return false;
	}
	return true;
}
int FileIn(const char* strFile, unsigned char*& inBuff)
{
	int iFileLen = 0, iBuffLen = 0;
	CFile file(strFile, CFile::modeRead);
	iFileLen = (int)file.GetLength();
	if (iFileLen > MAX_FILE)
	{
		printf("文件长度太大\n");
		goto out;
	}
	iBuffLen = iFileLen;
	inBuff = new unsigned char[iBuffLen];
	if (!inBuff) goto out;
	ZeroMemory(inBuff, iBuffLen);
	file.Read(inBuff, iFileLen);
	file.Close();
out:return iBuffLen;
}
void FileOut(const void *strOut, int len, const char* strFile)
{
	CFile outfile(strFile, CFile::modeCreate | CFile::modeWrite);
	outfile.Write(strOut, len);
	outfile.Close();
}
bool CheckParse(int argc, char** argv)
{
	bool bRes = false;
	if (argc != 4 && argc != 5) goto out;
	if (argc == 4 && argv[1][0] == 'k')
	{
		if (!isNumber(argv[2]) || !isNumber(argv[3]) ||
			atoi(argv[2]) > MAX_PRIME || atoi(argv[3]) > MAX_PRIME)
		{
			goto out;
		}
	}
	else if (argc == 5 && (argv[1][0] == 'e' || argv[1][0] == 'd'))
	{
		if (!isNumber(argv[3]) || !isNumber(argv[4]) ||
			atoi(argv[3]) > MAX_NUM || atoi(argv[4]) > MAX_NUM)
		{
			goto out;
		}
	}
	else
	{
		Usage(*argv);
	}
	bRes = true;
out:return bRes;
}
unsigned int kOption(unsigned int uiP, unsigned int uiQ)
{
	unsigned int uiRes = 0;
	if (!isPrimeNumber(uiP))
	{
		printf("P输入错误，P必须为(0, %d]的素数\n", MAX_PRIME);
		return uiRes;
	}
	if (!isPrimeNumber(uiQ))
	{
		printf("Q输入错误，Q必须为(0, %d)的素数\n", MAX_PRIME);
		return uiRes;
	}
	if (uiP == uiQ)
	{
		printf("P和Q不能相同\n");
		return uiRes;
	}
	printf("正在生成私钥d集合......\n");
	uiRes = MakePrivateKey(uiP, uiQ);
	return uiRes;
}
int main(int argc, char** argv)
{
	unsigned int p, q, d, n, e;
	CheckParse(argc, argv);
	d = 4828;
	if (argc == 4)
	{
		p = atoi(argv[2]);
		q = atoi(argv[3]);
		MakePrivateKey(p, q);
		MakePairkey(p, q, d);
		OutputKey();
	}
	else if (argc == 5)
	{
		char FileName[20];
		strcpy_s(FileName, argv[2]);
		int len;
		if (argv[1][0] == 'e')
		{
			unsigned char* inBuffer = (unsigned char*)malloc(MAX_FILE);
			int*cw = (int*)malloc(MAX_FILE);
			len = FileIn(FileName, inBuffer);
			e = atoi(argv[3]);
			n = atoi(argv[4]);
			RasEncrypt(n, e, (char*)inBuffer, len, cw);
			FileOut(cw, 4 * len, DECRYPT_FILE);
		}
		else if (argv[1][0] == 'd')
		{
			char* Buffer = (char*)malloc(MAX_FILE);
			int* cw = (int*)malloc(MAX_FILE);
			len = FileIn(FileName, (unsigned char*&)cw);
			d = atoi(argv[3]);
			n = atoi(argv[4]);
			RsaDecrypt(n, d, cw, len, Buffer);
			FileOut(Buffer, len / 4, ENCRYPT_FILE);
		}
	}
	return 0;

}