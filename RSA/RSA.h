#include <stdio.h>
#define MAX_NUM 63001
#define MAX_PRIME 251
#define OK 100
#define ERROR_NOEACHPRIME 101
#define ERROR_NOPUBLICKEY 102
#define ERROR_GENERROR 103
unsigned int MakePrivateKey(unsigned int uiP, unsigned int uiQ);
unsigned int GetPrivateKey(unsigned int iWhich);
unsigned int GetPairKey(unsigned int &d, unsigned int &e);
unsigned int MakePairkey(unsigned int uiP, unsigned int uiQ, unsigned int uiD);
void RasEncrypt(int n, int e, char* mw, int iLength, int* &cw);
void RsaDecrypt(int n, int d, int*&cw, int cLength, char *mw);
void OutputKey();