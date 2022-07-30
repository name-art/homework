/*
* 项目名称：SM3-Rho
* 简介：实现简单的Rho方法攻击SM3
* 完成人：徐骏骐
* SM3代码引用自https://blog.csdn.net/a344288106/article/details/80094878?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165891877616780366518718%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165891877616780366518718&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80094878-null-null.142^v35^pc_search_v2,185^v2^control&utm_term=sm3%E7%AE%97%E6%B3%95&spm=1018.2226.3001.4187
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
#define SM3_HASH_SIZE 32   //哈希值为32字节
typedef struct SM3Context
{
	unsigned int intermediateHash[SM3_HASH_SIZE / 4];
	unsigned char messageBlock[64];
} SM3Context;
unsigned char* SM3Calc(const char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);
#endif // _SM3_H_

static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)  //小端运行环境

#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )  //向左循环移位

void randperm(int Num)  //产生大概率不重复的随机数的函数
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

unsigned int* ReverseWord(unsigned int* word)  //四字节整型字节序反转
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

unsigned int T(int i)  //T函数
{
	if (i >= 0 && i <= 15)
		return 0x79CC4519;
	else if (i >= 16 && i <= 63)
		return 0x7A879D8A;
	else
		return 0;
}

unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)  //FF函数
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (X & Z) | (Y & Z);
	else
		return 0;
}

unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)  //GG函数
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (~X & Z);
	else
		return 0;
}

unsigned int P0(unsigned int X)  //P0函数
{
	return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

unsigned int P1(unsigned int X)    //P1函数
{
	return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

void SM3Init(SM3Context* context)  //初始化函数
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

void SM3ProcessMessageBlock(SM3Context* context)    //消息块处理
{
	int i;
	unsigned int W[68];
	unsigned int W_[64];
	unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

	for (i = 0; i < 16; i++)   //消息扩展
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
	//消息压缩
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
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])  //SM3函数
{
	SM3Context context;
	unsigned int i, remainder, bitLen;

	SM3Init(&context);  //初始化

	for (i = 0; i < messageLen / 64; i++)  //对消息进行分组
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		SM3ProcessMessageBlock(&context);
	}

	bitLen = messageLen * 8;  //对消息进行填充
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	remainder = messageLen % 64;
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;
	if (remainder <= 55)
	{
		//将高位的4个字节赋0
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		SM3ProcessMessageBlock(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		SM3ProcessMessageBlock(&context);
		//将高位的四个字节赋0
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		SM3ProcessMessageBlock(&context);
	}

	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);
	//将结果返回
	return digest;
}

int main(int argc, char* argv[])
{
	/*Rho方法：我们从[1，10000]中随机选取一个数，取到想要的那个数的概率为1/10000，为了增大
	概率，我们可以从中选出两个数，取到这两个数的差为想要的那个数的概率近似为1/5000。如此，
	我们选到想要的数的概率就提高了，我们还可以选择更多的数来大大提高我们选到想要的书的概率。
	对于整数分解问题，我们从[2,n-1]中选出k个数，如果其中两个数的差是n的因数或者与n的最大公
	因数大于1，那么我们就找到了相应的因数。这种方法可以应用于SM3的攻击，即已知一个报文和其
	对应的哈希值，我们想要找到和这个报文具有相同哈希值的伪造报文，那么我们可以从报文的取值
	空间中选择多个数进行哈希来找出想要的哈希值对应的报文。为了实现简易的Rho，我们可以找哈希
	值的前一个字节相同的两个报文，为了方便取数我们选取的报文为000-256。为了找到和200的哈希值
	的前一个字节相同的哈希值对应的报文，我们从000到256中随机选取两个数作差，对差值进行哈希来
	比对，这样做可以将找到对应报文的概率从1/256提升到1/128，例子为找到和200的哈希值的前一个
	字节ce相同的那个哈希值对应的报文。
	*/
	cout << "找出128个差值：" << endl;
	randperm(257);  //找到大概率不重复的128个[0,256]范围内的随机数
	cout << endl<< "将差值哈希：" << endl;
	int ilen = 3;  //消息的长度
	unsigned char output[32];   //消息的哈希值
	int i;
	char input[256];

	strcpy_s(input, "026");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	
	strcpy_s(input, "041");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	strcpy_s(input, "106");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	strcpy_s(input, "256");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	strcpy_s(input, "99");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}

	printf("\n");
	strcpy_s(input, "133");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");


	printf("\n");
	strcpy_s(input, "60");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "008");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input0中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "013");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");


	printf("\n");
	strcpy_s(input, "001");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "088");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "037");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "049");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "044");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "058");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "095");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "143");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "102");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "116");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "32");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "160");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "013");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "209");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "148");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "021");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "120");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "082");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "002");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "043");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "158");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "064");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "104");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "014");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "149");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "110");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "83");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "194");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "190");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "076");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "031");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "152");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "105");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "191");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "117");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "19");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "005");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "112");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "163");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "010");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "060");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "081");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "153");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "015");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "009");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "132");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "195");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "66");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "149");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "127");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "104");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "150");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "091");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "079");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "121");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "159");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "40");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "179");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "016");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "074");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "025");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "046");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "108");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "095");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "131");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "39");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "014");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "067");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "159");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "046");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "073");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "026");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "062");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "088");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "067");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "120");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "110");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "015");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "050");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "126");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "043");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "009");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "125");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "176");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "128");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "77");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "147");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "090");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "101");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "173");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "012");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "019");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "076");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "169");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "74");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "170");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "008");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "113");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "198");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "031");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "021");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "014");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "016");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "019");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "075");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "095");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "138");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "021");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "048");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "230");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "100");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "061");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "060");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");

	printf("\n");
	strcpy_s(input, "128");
	printf("Message:");
	printf("%s\n", input);
	SM3Calc(input, ilen, output);    //对input中的消息进行哈希
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)          //输出哈希值
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	//可以找到117对应的哈希值前一个字节为ce，与200的哈希值的前一个字节相同
}