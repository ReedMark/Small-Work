#include <stdio.h>
#include <string.h>
#include "DES.h"
#define ENCODE 0, 16, 1
#define DECODE 15, -1, -1
/*---------data----------*/
char inputkeys[16];
char inputkeyb[72];
char pc1keyb[128];
char outputkeyb[16][72];
char inputplaintext[128];
char inputplainb[72];
char ip1plainb[72];
char outputcipher[72];
char outputplain[128];
char hasharr[20] = "0123456789abcdef";
char reversehash[128];
/*-----------------------*/

/*字符数组转二进制*/
void CharToBin(char* input, char* output, int length)
{
	char tmp;
	for (int i = 0; i < length; ++i)
	{
		for (int j = 7, tmp = input[i]; j >= 0; --j)
		{
			output[(i << 3) + j] = tmp & 1;
			tmp >>= 1;
		}
	}
}
/*二进制转字符数组*/
void BinToChar(char* input, char* output, int length)
{
	for (int i = 0; i < (length << 3); ++i)
	{
		output[i >> 3] <<= 1;
		output[i >> 3] |= input[i];
	}
	output[length << 3] = 0;
}

/*获取密钥*/
void getkey()
{
	char* ptr = pc1keyb;
	for (int i = 0; i < 8; ++i)
	{
		inputkeys[i] <<= 1;  //去奇偶校验
	}
	CharToBin(inputkeys, inputkeyb, 8);
	transposition(inputkeyb, pc1keyb, PC1, 56);
	for (int i = 0; i < 16; ++i)
	{
		for (int j = 0; j < key_mov[i]; ++j, ptr++)
		{
			ptr[56] = ptr[28];
			ptr[28] = ptr[0];
		}
		transposition(ptr, outputkeyb[i], PC2, 48);
	}
}

void transposition(char* input, char* output, char* offset, int length)
{
	for (int i = 0; i < length; ++i)
	{
		output[i] = input[offset[i] - 1];
	}
}

void DES(char* input, int start, int end, int step)
{
	char preRight[48];
	char eplainb[56];
	char splains[12];
	char splainb[48];
	char pplainb[48];
	char ip2plainb[72];
	CharToBin(input, inputplainb, 8);
	transposition(inputplainb, ip1plainb, IP1, 64);
	for (; start != end; start += step)
	{
		memcpy(preRight, ip1plainb + 32, 32);
		transposition(ip1plainb + 32, eplainb, E, 48);
		for (int i = 0; i < 48; ++i)
		{
			eplainb[i] ^= outputkeyb[start][i];
		}
		for (int i = 0; i < 48; i += 6)
		{
			int row = (eplainb[i] << 1) | eplainb[i + 5];
			int col = (eplainb[i + 1] << 3) | (eplainb[i + 2] << 2) | (eplainb[i + 3] << 1) | eplainb[i + 4];
			splains[i / 12] = (splains[i / 12] << 4) | S[i / 6][row][col];
		}
		CharToBin(splains, splainb, 4);
		transposition(splainb, pplainb, P, 32);
		for (int i = 0; i < 32; ++i)
		{
			ip1plainb[i + 32] ^= ip1plainb[i];
		}
		memcpy(ip1plainb, preRight, 32);
	}
	memcpy(inputplainb, ip1plainb + 32, 32);
	memcpy(inputplainb + 32, ip1plainb, 32);
	transposition(inputplainb, ip2plainb, IP2, 64);
	if (step == 1)
	{
		ciphertrans(ip2plainb, outputcipher);
	}
	else
	{
		BinToChar(ip2plainb, outputplain, 8);
	}
}

void ciphertrans(char* input, char* output)
{
	for (int i = 0; i < 16; ++i)
	{
		output[i] = 0;
		for (int j = 0; j < 4; ++j)
		{
			output[i] = (output[i] << 1) | input[i * 4 + j];
		}
		output[i] = hasharr[output[i]];
	}
	output[16] = 0;
}

void ciprestore(char* input, char* output)
{
	for (char i = 0; i < 16; ++i)
	{
		reversehash[hasharr[i]] = i;
	}
	for (int i = 0; i < 16; ++i)
	{
		output[i >> 1] = (output[i >> 1] << 4) | reversehash[input[i]];
	}
}

int main(int arg, char* arv[])
{
	char plaintext[128];
	char tmp[128];
	if (arg < 3)
	{
		printf("input err");
		return 0;
	}
	char mode = arv[1][0];
	strcpy(inputkeys, arv[2]);
	strcpy(plaintext,arv[3]);
	getkey();
	if (mode == 'e')
	{
		for (int i = 0; plaintext[i]; i += 8)
		{
			DES(plaintext + i, ENCODE);
			printf("%s", outputcipher);
		}
	}
	else if (mode == 'd')
	{
		for (int i = 0; plaintext[i]; i += 16)
		{
			ciprestore(plaintext + i, tmp);
			DES(tmp, DECODE);
			printf("%s", outputplain);
		}
	}
	else
	{
		printf("input err");
	}
	printf("\n");
	getchar();
	return 0;
}