#include <stdio.h>
#include <string.h>
#include "DES.h"
#define ENCODE 0, 16, 1
#define DECODE 15, -1, -1
int output_key[16][48];
char output_ciphertext[128];
char output_plaintext[128];
void CharToBin(char* input_char, int* output_bin, int length)
{
	for (int i = 0; i < length; ++i)
	{
		char c = input_char[i];
		for (int j = 7; j >= 0; --j)
		{
			output_bin[(i << 3) + j] = c & 1;
			c >>= 1;
		}
	}
}

void BinToChar(int* input_bin, char* output_char, int length)
{
	for (int i = 0; i < length; ++i)
	{
		output_char[i >> 3] <<= 1;
		output_char[i >> 3] |= input_bin[i];
	}
    output_char[length] = 0;
}

void display_hex(int* input_bin, char* output_hex, int length)
{
	char hex_arr[20] = "0123456789abcdef";
	for (int i = 0; i < (length >> 2); ++i)
	{
		output_hex[i] = 0;
	}
	for (int i = 0; i < length; ++i)
	{
		output_hex[i >> 2] <<= 1;
		output_hex[i >> 2] |= input_bin[i];
	}
	for (int i = 0; i < (length >> 2); ++i)
	{
		output_hex[i] = hex_arr[output_hex[i]];
	}
}

void restore_bin(char* input_hex, int* output_bin, int length)
{
	char hex_arr_index[128];
	char hex_arr[20] = "0123456789abcdef";
	for (int i = 0; i < 16; ++i)
	{
		hex_arr_index[hex_arr[i]] = i;
	}
	for (int i = 0; i < length; ++i)
	{
		char c = input_hex[i];
		int real_num = hex_arr_index[c];
		for (int j = 3; j >= 0; --j)
		{
			output_bin[i * 4 + j] = real_num & 1;
			real_num >>= 1;
		}
	}
}

void getkeys(char* input_key)
{
	int key_arr[64];
	int key_pc1_arr[56];
	int key_left[28];
	int key_right[28];
	int key_combation[56];
	int left_bit;
	CharToBin(input_key, key_arr, 8);
	transposition(key_arr, key_pc1_arr, PC1, 56);
	for (int i = 0; i < 28; ++i)
	{
		key_left[i] = key_pc1_arr[i];
		key_right[i] = key_pc1_arr[i + 28];
	}
	for (int i = 0; i < 16; ++i)
	{
		if (key_mov[i] == 1)
		{
			for (int j = 0; j < 28; ++j)
			{
				left_bit = key_left[0];
				key_left[j] = key_left[j + 1];
				key_left[27] = left_bit;
			}
		}
		if (key_mov[i] == 2)
		{
			for (int k = 0; k <= 1; ++k)
			{
				for (int j = 0; j < 28; ++j)
				{
					left_bit = key_left[0];
					key_left[j] = key_left[j + 1];
					key_left[27] = left_bit;
				}
			}
		}
		for (int j = 0; j < 28; ++j)
		{
			key_combation[j] = key_left[j];
			key_combation[j + 28] = key_right[j];
		}
		transposition(key_combation, output_key[i], PC2, 48);
	}
}

void transposition(int* input_arr, int* output_arr, int* offset, int length)
{
	for (int i = 0; i < length; ++i)
	{
		output_arr[i] = input_arr[offset[i] - 1];
	}
}

void IntToBin(int* input_arr, int* output_bin, int length)
{
	for (int i = 0; i < length; ++i)
	{
		int num = input_arr[i];
		for (int j = 3; j >= 0; --j)
		{
			output_bin[i * 4 + j] = num & 1;
			num >>= 1;
		}
	}
}

void DES(int* input_b, int start, int end, int step)
{
	int ip1_b[64];
	int pre_right_b[32];
	int e_b[48];
	int s_num[8];
	int s_b[32];
	int p_b[32];
	int f16[64];
	int ip2_b[64];
	transposition(input_b, ip1_b, IP1, 64);
	for (; start != end; start += step)
	{
		for (int i = 32; i < 64; ++i)
		{
			pre_right_b[i - 32] = ip1_b[i];
		}
		transposition(ip1_b + 32, e_b, E, 48);
		for (int i = 0; i < 48; ++i)
		{
			e_b[i] ^= output_key[start][i];
		}
		for (int i = 0; i < 48; i += 6)
		{
			int row = e_b[i] * 2 + e_b[i + 5];
			int col = e_b[i + 1] * 8 + e_b[i + 2] * 4 + e_b[i + 3] * 2 + e_b[i + 4];
			s_num[i / 6] = S[i / 6][row][col];
		}
		IntToBin(s_num, s_b, 8);
		transposition(s_b, p_b, P, 32);
		for (int i = 0; i < 32; ++i)
		{
			ip1_b[i + 32] = ip1_b[i] ^ p_b[i];
		}
		for (int i = 0; i < 32; ++i)
		{
			ip1_b[i] = pre_right_b[i];
		}
	}
	for (int i = 0; i < 32; ++i)
	{
		f16[i] = ip1_b[i + 32];
		f16[i + 32] = ip1_b[i];
	}
	transposition(f16, ip2_b, IP2, 64);
	if (step == 1)
	{
		display_hex(ip2_b, output_ciphertext, 64);
	}
	else
	{
		BinToChar(ip2_b, output_plaintext, 64);
	}
}

int main(int args, char* arv[])
{
	char input_text[128];
	int input_bin[64];
	char input_key[8];
	char mode = arv[1][0];
	strcpy(input_key, arv[2]);
	strcpy(input_text, arv[3]);
	getkeys(input_key);
	if (mode == 'e')
	{
		for (int i = 0; input_text[i]; i += 8)
		{
			CharToBin(input_text + i, input_bin, 64);
			DES(input_bin, ENCODE);
			printf("%s", output_ciphertext);
		}
	}
	else if (mode == 'd')
	{
		for (int i = 0; input_text[i]; i += 16)
		{
			restore_bin(input_text + i, input_bin, 16);
			DES(input_bin, DECODE);
			printf("%s", output_plaintext);
		}
	}
	getchar();
	return 0;
}