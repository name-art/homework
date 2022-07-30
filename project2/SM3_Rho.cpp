/*
* ��Ŀ���ƣ�SM3-Rho
* ��飺ʵ�ּ򵥵�Rho��������SM3
* ����ˣ��쿥��
* SM3����������https://blog.csdn.net/a344288106/article/details/80094878?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165891877616780366518718%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165891877616780366518718&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80094878-null-null.142^v35^pc_search_v2,185^v2^control&utm_term=sm3%E7%AE%97%E6%B3%95&spm=1018.2226.3001.4187
*/

#include <stdio.h>
#include <memory.h>
#include<string.h>
#include<iostream>
#include<stdlib.h>
#include<vector>
#include<algorithm>

using namespace std;
#pragma once
#ifndef _SM3_H_
#define _SM3_H_
#define SM3_HASH_SIZE 32   //��ϣֵΪ32�ֽ�
typedef struct SM3Context
{
	unsigned int intermediateHash[SM3_HASH_SIZE / 4];
	unsigned char messageBlock[64];
} SM3Context;
unsigned char* SM3Calc(const char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);
#endif // _SM3_H_

static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)  //С�����л���

#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )  //����ѭ����λ

void randperm(int Num)  //��������ʲ��ظ���������ĺ���
{
	vector<int> temp;
	for (int i = 0; i < Num; ++i)
	{
		temp.push_back(i + 1);
	}
	random_shuffle(temp.begin(), temp.end());

	for (int i = 0; i < temp.size()/2; i++)
	{
		cout << abs(temp[i]-temp[i+127]) << " ";
	}
}

unsigned int* ReverseWord(unsigned int* word)  //���ֽ������ֽ���ת
{
	unsigned char* byte, temp;
	byte = (unsigned char*)word;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;
	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return word;
}

unsigned int T(int i)  //T����
{
	if (i >= 0 && i <= 15)
		return 0x79CC4519;
	else if (i >= 16 && i <= 63)
		return 0x7A879D8A;
	else
		return 0;
}

unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)  //FF����
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (X & Z) | (Y & Z);
	else
		return 0;
}

unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)  //GG����
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (~X & Z);
	else
		return 0;
}

unsigned int P0(unsigned int X)  //P0����
{
	return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

unsigned int P1(unsigned int X)    //P1����
{
	return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

void SM3Init(SM3Context* context)  //��ʼ������
{
	context->intermediateHash[0] = 0x7380166F;
	context->intermediateHash[1] = 0x4914B2B9;
	context->intermediateHash[2] = 0x172442D7;
	context->intermediateHash[3] = 0xDA8A0600;
	context->intermediateHash[4] = 0xA96F30BC;
	context->intermediateHash[5] = 0x163138AA;
	context->intermediateHash[6] = 0xE38DEE4D;
	context->intermediateHash[7] = 0xB0FB0E4E;
}

void SM3ProcessMessageBlock(SM3Context* context)    //��Ϣ�鴦��
{
	int i;
	unsigned int W[68];
	unsigned int W_[64];
	unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

	for (i = 0; i < 16; i++)   //��Ϣ��չ
	{
		W[i] = *(unsigned int*)(context->messageBlock + i * 4);
		if (IsLittleEndian())
			ReverseWord(W + i);
	}
	for (i = 16; i < 68; i++)
	{
		W[i] = P1(W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15))
			^ LeftRotate(W[i - 13], 7)
			^ W[i - 6];
	}
	for (i = 0; i < 64; i++)
	{
		W_[i] = W[i] ^ W[i + 4];
	}
	//��Ϣѹ��
	A = context->intermediateHash[0];
	B = context->intermediateHash[1];
	C = context->intermediateHash[2];
	D = context->intermediateHash[3];
	E = context->intermediateHash[4];
	F = context->intermediateHash[5];
	G = context->intermediateHash[6];
	H = context->intermediateHash[7];
	for (i = 0; i < 64; i++)
	{
		SS1 = LeftRotate((LeftRotate(A, 12) + E + LeftRotate(T(i), i)), 7);
		SS2 = SS1 ^ LeftRotate(A, 12);
		TT1 = FF(A, B, C, i) + D + SS2 + W_[i];
		TT2 = GG(E, F, G, i) + H + SS1 + W[i];
		D = C;
		C = LeftRotate(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = LeftRotate(F, 19);
		F = E;
		E = P0(TT2);
	}
	context->intermediateHash[0] ^= A;
	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;
	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;
	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;
	context->intermediateHash[7] ^= H;
}

unsigned char* SM3Calc(const char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])  //SM3����
{
	SM3Context context;
	unsigned int i, remainder, bitLen;

	SM3Init(&context);  //��ʼ��

	for (i = 0; i < messageLen / 64; i++)  //����Ϣ���з���
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		SM3ProcessMessageBlock(&context);
	}

	bitLen = messageLen * 8;  //����Ϣ�������
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	remainder = messageLen % 64;
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;
	if (remainder <= 55)
	{
		//����λ��4���ֽڸ�0
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		SM3ProcessMessageBlock(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		SM3ProcessMessageBlock(&context);
		//����λ���ĸ��ֽڸ�0
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		SM3ProcessMessageBlock(&context);
	}

	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);
	//���������
	return digest;
}

int main(int argc, char* argv[])
{
	/*Rho���������Ǵ�[1��10000]�����ѡȡһ������ȡ����Ҫ���Ǹ����ĸ���Ϊ1/10000��Ϊ������
	���ʣ����ǿ��Դ���ѡ����������ȡ�����������Ĳ�Ϊ��Ҫ���Ǹ����ĸ��ʽ���Ϊ1/5000����ˣ�
	����ѡ����Ҫ�����ĸ��ʾ�����ˣ����ǻ�����ѡ��������������������ѡ����Ҫ����ĸ��ʡ�
	���������ֽ����⣬���Ǵ�[2,n-1]��ѡ��k��������������������Ĳ���n������������n�����
	��������1����ô���Ǿ��ҵ�����Ӧ�����������ַ�������Ӧ����SM3�Ĺ���������֪һ�����ĺ���
	��Ӧ�Ĺ�ϣֵ��������Ҫ�ҵ���������ľ�����ͬ��ϣֵ��α�챨�ģ���ô���ǿ��Դӱ��ĵ�ȡֵ
	�ռ���ѡ���������й�ϣ���ҳ���Ҫ�Ĺ�ϣֵ��Ӧ�ı��ġ�Ϊ��ʵ�ּ��׵�Rho�����ǿ����ҹ�ϣ
	ֵ��ǰһ���ֽ���ͬ���������ģ�Ϊ�˷���ȡ������ѡȡ�ı���Ϊ000-256��Ϊ���ҵ���200�Ĺ�ϣֵ
	��ǰһ���ֽ���ͬ�Ĺ�ϣֵ��Ӧ�ı��ģ����Ǵ�000��256�����ѡȡ����������Բ�ֵ���й�ϣ��
	�ȶԣ����������Խ��ҵ���Ӧ���ĵĸ��ʴ�1/256������1/128������Ϊ�ҵ���200�Ĺ�ϣֵ��ǰһ��
	�ֽ�ce��ͬ���Ǹ���ϣֵ��Ӧ�ı��ġ�
	*/
	cout << "�ҳ�128����ֵ��" << endl;
	randperm(257);  //�ҵ�����ʲ��ظ���128��[0,256]��Χ�ڵ������
	cout << endl<< "����ֵ��ϣ��" << endl;
	int ilen = 3;  //��Ϣ�ĳ���
	unsigned char output[32];   //��Ϣ�Ĺ�ϣֵ
	int i;
	char input[256];

	strcpy_s(input, "026");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	
	strcpy_s(input, "041");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	strcpy_s(input, "106");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	strcpy_s(input, "256");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	strcpy_s(input, "99");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}

	printf("\n");
	strcpy_s(input, "133");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");


	printf("\n");
	strcpy_s(input, "60");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "008");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "013");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");


	printf("\n");
	strcpy_s(input, "001");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "088");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "037");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "049");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "044");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "058");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "095");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "143");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "102");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "116");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "32");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "160");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "013");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "209");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "148");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "021");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "120");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "082");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "002");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "043");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "158");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "064");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "104");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "014");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "149");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "110");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "83");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "194");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "190");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "076");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "031");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "152");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "105");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "191");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "117");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "19");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "005");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "112");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "163");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "010");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "060");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "081");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "153");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "015");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "009");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "132");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "195");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "66");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "149");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "127");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "104");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "150");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "091");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "079");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "121");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "159");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "40");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "179");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "016");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "074");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "025");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "046");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "108");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "095");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "131");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "39");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "014");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "067");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "159");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "046");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "073");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "026");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "062");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "088");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "067");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "120");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "110");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "015");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "050");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "126");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "043");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "009");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "125");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "176");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "128");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "77");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "147");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "090");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "101");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "173");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "012");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "019");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "076");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "169");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "74");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "170");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "008");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "113");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "198");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "031");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "021");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "014");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "016");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "019");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "075");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "095");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "138");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "021");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "048");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "230");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "100");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "061");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "060");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "128");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //��input�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	//�����ҵ�117��Ӧ�Ĺ�ϣֵǰһ���ֽ�Ϊce����200�Ĺ�ϣֵ��ǰһ���ֽ���ͬ
}