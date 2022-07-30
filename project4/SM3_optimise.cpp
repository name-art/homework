/*
* ��Ŀ���ƣ�SM3�Ż�
* ��飺�Ż�SM3��Ч��
* ����ˣ��쿥��
* SM3����������https://blog.csdn.net/a344288106/article/details/80094878?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165891877616780366518718%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165891877616780366518718&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80094878-null-null.142^v35^pc_search_v2,185^v2^control&utm_term=sm3%E7%AE%97%E6%B3%95&spm=1018.2226.3001.4187
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
int ilen = 2;  //��Ϣ�ĳ���
unsigned char output[32];   //��Ϣ�Ĺ�ϣֵ
int i;
unsigned char input0[256] = "00";  //��ϢΪ��00�����浽input0��
void q1(int kl)   //���̺߳���
{
	for (int i = 0; i < kl; i++)
	{
		SM3Calc(input0, ilen, output);
	}
}
int main(int argc, char* argv[])
{
	/*ѭ��չ������ˮ�ߵ��Ż���������SM3�㷨û�п������õ�ѭ����������Ч����
	���߳̿������� SM3 ��������ļ��١����ӳٷ������ڵ��μ��ܽ��еĲ�������
	�Խ�ǿ�����Խ��еĲ��в������٣����Ѹ���ͬ���̷߳��䲻ͬ���ֵĹ�������
	���ö��Эͬ������Ŀ�ģ����������������������ٶȣ���ʵ�� SM3 �Ĺ�����
	ʹ�ö��̷߳���Ч�����ã����Բ��ʺ�ʹ�ö��̣߳��������������棬���ǿ���
	�������ӽ��ܹ�����Ϊһ�κ������ã��Ӷ�ʹ�ö��̣߳�������� cpu ��Դ����
	��������������������������λʱ�������ܼ��ܵ��ֽ��������ʹ�ö��߳�Ч��
	�Ϻá���Ҫʵ�ֶ��̼߳��ܶ�����ģ���������һ������ q1������ kl Ϊһ�μ�
	�ܵ��������� q1 ����������� kl �εļӽ��ܹ������˺������Ա�����̵߳�
	�ôӶ��ﵽʹ�ö��̵߳�Ŀ�ġ����в�ͬ���߳������ԣ��Աȵõ����߳��Ż���
	Ч�������߳��Ǵ���һ���߳������� 100000 �μӽ��ܲ�����2 �߳��Ǵ�������
	�̷ֱ߳����50000 �μӽ��ܲ�����4 �߳��Ǵ����ĸ��̷ֱ߳���� 25000 ��
	�ӽ��ܲ��������Դ����ƣ�ͨ���Ƚϲ�ͬ���߳�������ͬ����Ĵ������õ�ʱ��
	����ʾ����Ч����ʹ�õļ�ʱ����΢�뼶��ʱ�������Խ�Ϊ׼ȷ�ز���������ʱ
	�䡣�Զ��߳�Ϊ������ʼ��ʱ�󴴽������߳� e1 �� e2�����ú��� q1��������
	�̶����� 50000�μӽ��ܲ���Ȼ�����.join()������֤�̹߳���������ɣ�������ʱ��*/
	
		auto start = steady_clock::now();
		thread t(q1, 100000);
		t.join();
		auto end = steady_clock::now();
		auto last = duration_cast<microseconds>(end - start);
		cout << "���߳�����ʱ��:" << last.count() << "um" << endl;

		auto start4 = steady_clock::now();
		thread e1(q1, 50000);
		thread e2(q1, 50000);
		e1.join();
		e2.join();
		auto end4 = steady_clock::now();
		auto last4 = duration_cast<microseconds>(end4 - start4);
		cout << "2�߳�����ʱ��:" << last4.count() << "um" << endl;

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
		cout << "4�߳�����ʱ��:" << last1.count() << "um" << endl;

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
		cout << "8�߳�����ʱ��:" << last2.count() << "um" << endl;

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
		cout << "16�߳�����ʱ��:" << last3.count() << "um" << endl;
		return 0;
}