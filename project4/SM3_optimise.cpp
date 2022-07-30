/*
* 项目名称：SM3优化
* 简介：优化SM3的效率
* 完成人：徐骏骐
* SM3代码引用自https://blog.csdn.net/a344288106/article/details/80094878?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165891877616780366518718%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165891877616780366518718&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80094878-null-null.142^v35^pc_search_v2,185^v2^control&utm_term=sm3%E7%AE%97%E6%B3%95&spm=1018.2226.3001.4187
*/

#include <stdio.h>
#include <memory.h>
#include<string.h>
#include<iostream>
#include<chrono>
#include<thread>
using namespace std::chrono;
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
unsigned char* SM3Calc(const unsigned char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);
#endif // _SM3_H_

static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)  //小端运行环境

#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )  //向左循环移位

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

unsigned char* SM3Calc(const unsigned char* message,
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
int ilen = 2;  //消息的长度
unsigned char output[32];   //消息的哈希值
int i;
unsigned char input0[256] = "00";  //消息为“00”，存到input0里
void q1(int kl)   //多线程函数
{
	for (int i = 0; i < kl; i++)
	{
		SM3Calc(input0, ilen, output);
	}
}
int main(int argc, char* argv[])
{
	/*循环展开、流水线的优化方法由于SM3算法没有可以利用的循环而难以奏效，而
	多线程可以用于 SM3 加密运算的加速。在延迟方面由于单次加密进行的操作关联
	性较强，可以进行的并行操作较少，很难给不同的线程分配不同部分的工作来达
	到让多核协同工作的目的，很难在这个方面提高运行速度，在实现 SM3 的过程中
	使用多线程方法效果不好，所以不适合使用多线程；而在吞吐量方面，我们可以
	将整个加解密工作作为一次函数调用，从而使用多线程，充分利用 cpu 资源，这
	样可以明显提升吞吐量，即单位时间内所能加密的字节数，因此使用多线程效果
	较好。想要实现多线程加密多个明文，可以声明一个函数 q1，参数 kl 为一次加
	密的数量，在 q1 函数里面进行 kl 次的加解密工作。此函数可以被多个线程调
	用从而达到使用多线程的目的。进行不同的线程数测试，对比得到多线程优化的
	效果。单线程是创建一个线程来进行 100000 次加解密操作；2 线程是创建两个
	线程分别进行50000 次加解密操作；4 线程是创建四个线程分别进行 25000 次
	加解密操作……以此类推，通过比较不同的线程数加密同样多的次数所用的时间
	来显示加速效果。使用的计时器是微秒级计时器，可以较为准确地测量出运行时
	间。以二线程为例，开始计时后创建两个线程 e1 和 e2，调用函数 q1，两个线
	程都进行 50000次加解密操作然后加入.join()函数保证线程工作运行完成，结束计时。*/
	
		auto start = steady_clock::now();
		thread t(q1, 100000);
		t.join();
		auto end = steady_clock::now();
		auto last = duration_cast<microseconds>(end - start);
		cout << "单线程所用时间:" << last.count() << "um" << endl;

		auto start4 = steady_clock::now();
		thread e1(q1, 50000);
		thread e2(q1, 50000);
		e1.join();
		e2.join();
		auto end4 = steady_clock::now();
		auto last4 = duration_cast<microseconds>(end4 - start4);
		cout << "2线程所用时间:" << last4.count() << "um" << endl;

		auto start1 = steady_clock::now();
		thread t1(q1, 25000);
		thread t2(q1, 25000);
		thread t3(q1, 25000);
		thread t4(q1, 25000);
		t1.join();
		t2.join();
		t3.join();
		t4.join();
		auto end1 = steady_clock::now();
		auto last1 = duration_cast<microseconds>(end1 - start1);
		cout << "4线程所用时间:" << last1.count() << "um" << endl;

		auto start2 = steady_clock::now();
		thread k1(q1, 12500);
		thread k2(q1, 12500);
		thread k3(q1, 12500);
		thread k4(q1, 12500);
		thread k5(q1, 12500);
		thread k6(q1, 12500);
		thread k7(q1, 12500);
		thread k8(q1, 12500);
		k1.join();
		k2.join();
		k3.join();
		k4.join();
		k5.join();
		k6.join();
		k7.join();
		k8.join();
		auto end2 = steady_clock::now();
		auto last2 = duration_cast<microseconds>(end2 - start2);
		cout << "8线程所用时间:" << last2.count() << "um" << endl;

		auto start3 = steady_clock::now();
		thread o1(q1, 6250);
		thread o2(q1, 6250);
		thread o3(q1, 6250);
		thread o4(q1, 6250);
		thread o5(q1, 6250);
		thread o6(q1, 6250);
		thread o7(q1, 6250);
		thread o8(q1, 6250);
		thread o9(q1, 6250);
		thread o10(q1, 6250);
		thread o11(q1, 6250);
		thread o12(q1, 6250);
		thread o13(q1, 6250);
		thread o14(q1, 6250);
		thread o15(q1, 6250);
		thread o16(q1, 6250);
		o1.join();
		o2.join();
		o3.join();
		o4.join();
		o5.join();
		o6.join();
		o7.join();
		o8.join();
		o9.join();
		o10.join();
		o11.join();
		o12.join();
		o13.join();
		o14.join();
		o15.join();
		o16.join();
		auto end3 = steady_clock::now();
		auto last3 = duration_cast<microseconds>(end3 - start3);
		cout << "16线程所用时间:" << last3.count() << "um" << endl;
		return 0;
}