/*
* ��Ŀ���ƣ�SM3���չ���
* ��飺ʵ�ּ򵥵�SM3���չ���
* ����ˣ��쿥��
* SM3����������https://blog.csdn.net/a344288106/article/details/80094878?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165891877616780366518718%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165891877616780366518718&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80094878-null-null.142^v35^pc_search_v2,185^v2^control&utm_term=sm3%E7%AE%97%E6%B3%95&spm=1018.2226.3001.4187
*/

#include <stdio.h>
#include <memory.h>
#include<string.h>
#include<iostream>

#pragma once
#ifndef _SM3_H_
#define _SM3_H_
#define SM3_HASH_SIZE 32   //��ϣֵΪ32�ֽ�
typedef struct SM3Context
{
	unsigned int intermediateHash[SM3_HASH_SIZE / 4];
	unsigned char messageBlock[64];
} SM3Context;
unsigned char* SM3Calc(const unsigned char* message,   
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);
#endif // _SM3_H_

static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)  //С�����л���

#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )  //����ѭ����λ

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

unsigned char* SM3Calc(const unsigned char* message,
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
	/*���չ��������ø������е��������⣬�ҵ���ͻ�Ĺ�ϣֵ��α�챨�ģ�ʹ�����֤�㷨ʧЧ��������ײ��
	ͨ���������֪�����չ�������������ﵽ1.7 * (n) ^ 1 / 2ʱ�����г�������֮һ�ĳɹ��ʡ�Ϊ��ʵ�ּ��׵����չ�����
	���ǿ��Խ�n��Ϊ256�����ҵ���ϣֵ��ǰһ���ֽڣ���32���ֽڣ���ͬ��������Ϣ, ��ʱ������Ҫ���27.2����Ϣ��
	�������ǿ��԰���Ϣ�ĳ�����Ϊ��λ��������ʵ����٣����30����λ����Ϣ���ҵ���ϣֵǰһ���ֽ���ͬ����ײ*/
	int ilen = 2;  //��Ϣ�ĳ���
	unsigned char output[32];   //��Ϣ�Ĺ�ϣֵ
	int i;

	unsigned char input0[256] = "00";  //��ϢΪ��00�����浽input0��
	printf("Message:");
	printf("%s\n", input0);
	SM3Calc(input0, ilen, output);    //��input0�е���Ϣ���й�ϣ
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //�����ϣֵ
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input1[256] = "01";   //�ظ�30�飬��Ӧ�ڶ�30����Ϣ���й�ϣ�����
	printf("Message:");
	printf("%s\n", input1);
	SM3Calc(input1, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	
	unsigned char input2[256] = "02";
	printf("Message:");
	printf("%s\n", input2);
	SM3Calc(input2, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input3[256] = "03";
	printf("Message:");
	printf("%s\n", input3);
	SM3Calc(input3, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input4[256] = "04";
	printf("Message:");
	printf("%s\n", input4);
	SM3Calc(input4, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input5[256] = "05";
	printf("Message:");
	printf("%s\n", input5);
	SM3Calc(input5, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	
	unsigned char input6[256] = "06";
	printf("Message:");
	printf("%s\n", input6);
	SM3Calc(input6, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input7[256] = "07";
	printf("Message:");
	printf("%s\n", input7);
	SM3Calc(input7, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input8[256] = "08";
	printf("Message:");
	printf("%s\n", input8);
	SM3Calc(input8, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input9[256] = "09";
	printf("Message:");
	printf("%s\n", input9);
	SM3Calc(input9, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input10[256] = "10";
	printf("Message:");
	printf("%s\n", input10);
	SM3Calc(input10, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input11[256] = "11";
	printf("Message:");
	printf("%s\n", input11);
	SM3Calc(input11, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input12[256] = "12";
	printf("Message:");
	printf("%s\n", input12);
	SM3Calc(input12, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input13[256] = "13";
	printf("Message:");
	printf("%s\n", input13);
	SM3Calc(input13, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input14[256] = "14";
	printf("Message:");
	printf("%s\n", input14);
	SM3Calc(input14, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input15[256] = "15";
	printf("Message:");
	printf("%s\n", input15);
	SM3Calc(input15, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input16[256] = "16";
	printf("Message:");
	printf("%s\n", input16);
	SM3Calc(input16, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input17[256] = "17";
	printf("Message:");
	printf("%s\n", input17);
	SM3Calc(input17, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input18[256] = "18";
	printf("Message:");
	printf("%s\n", input18);
	SM3Calc(input18, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input19[256] = "19";
	printf("Message:");
	printf("%s\n", input19);
	SM3Calc(input19, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input20[256] = "20";
	printf("Message:");
	printf("%s\n", input20);
	SM3Calc(input20, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input21[256] = "21";
	printf("Message:");
	printf("%s\n", input21);
	SM3Calc(input21, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input22[256] = "22";
	printf("Message:");
	printf("%s\n", input22);
	SM3Calc(input22, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input23[256] = "23";
	printf("Message:");
	printf("%s\n", input23);
	SM3Calc(input23, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input24[256] = "24";
	printf("Message:");
	printf("%s\n", input24);
	SM3Calc(input24, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input25[256] = "25";
	printf("Message:");
	printf("%s\n", input25);
	SM3Calc(input25, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input26[256] = "26";
	printf("Message:");
	printf("%s\n", input26);
	SM3Calc(input26, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input27[256] = "27";
	printf("Message:");
	printf("%s\n", input27);
	SM3Calc(input27, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input28[256] = "28";
	printf("Message:");
	printf("%s\n", input28);
	SM3Calc(input28, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input29[256] = "29";
	printf("Message:");
	printf("%s\n", input29);
	SM3Calc(input29, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	unsigned char input30[256] = "30";
	printf("Message:");
	printf("%s\n", input30);
	SM3Calc(input30, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	//�����н���п����ҵ�04�Ĺ�ϣֵ��27�Ĺ�ϣֵ��ǰһ���ֽ���ͬ������bd��ʵ���˼��׵Ĺ���
}