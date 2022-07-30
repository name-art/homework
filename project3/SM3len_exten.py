#项目名称：SM3优化
#简介：对SM3进行优化
#完成人：徐骏骐
#SM3代码引用自https://blog.csdn.net/a344288106/article/details/80094878?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165891877616780366518718%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165891877616780366518718&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80094878-null-null.142^v35^pc_search_v2,185^v2^control&utm_term=sm3%E7%AE%97%E6%B3%95&spm=1018.2226.3001.4187
# 先随机生成一个报文，然后使用SM3算出报文的哈希值1，再将哈希值1按照四字节为一组分成八组，
# 将其作为新的向量来加密附加的消息，得到哈希值2，最后将报文长度对应的代替串+填充+附加的消
# 息组成新的报文，将其进行哈希，得到哈希值3，对比哈希值2和哈希值3，若相等则长度扩展攻击成功。

import random
import math
import binascii

IV = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]

T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]

def sm3_ff(x, y, z, j):
    if 0 <= j and j < 16:
        m = x ^ y ^ z
    elif 16 <= j and j < 64:
        m = (x & y) | (x & z) | (y & z)
    return m

def sm3_gg(x, y, z, j):
    if 0 <= j and j < 16:
        m = x ^ y ^ z
    elif 16 <= j and j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        m = (x & y) | ((~ x) & z)
    return m

def sm3_p0(x):
    return x ^ (zh(x, 9 % 32)) ^ (zh(x, 17 % 32))

def sm3_p1(x):
    return x ^ (zh(x, 15 % 32)) ^ (zh(x, 23 % 32))

def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i*4,(i+1)*4):
            data = data + b_i[k]*weight
            weight = int(weight/0x100)
        w.append(data)
    for j in range(16, 68):
        w.append(0)
        w[j] = sm3_p1(w[j-16] ^ w[j-9] ^ (zh(w[j-3], 15 % 32))) ^ (zh(w[j-13], 7 % 32)) ^ w[j-6]
        str1 = "%08x" % w[j]
    w_1 = []
    for j in range(0, 64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j+4]
        str1 = "%08x" % w_1[j]
    a, b, c, d, e, f, g, h = v_i
    for j in range(0, 64):
        ss_1 = zh(
            ((zh(a, 12 % 32)) +
            e +
            (zh(T_j[j], j % 32))) & 0xffffffff, 7 % 32
        )
        ss_2 = ss_1 ^ (zh(a, 12 % 32))
        tt_1 = (sm3_ff(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (sm3_gg(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = zh(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = zh(f, 19 % 32)
        f = e
        e = sm3_p0(tt_2)
        a, b, c, d, e, f, g, h = map(
            lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])
    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]
def sm3_hash(msg, ano):   #可以设定向量ano的哈希函数
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64
    for i in range(reserve1, range_end):
        msg.append(0x00)
    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])
    group_count = round(len(msg) / 64) - 1
    B = []
    for i in range(0, group_count):
        B.append(msg[(i + 1)*64:(i+2)*64])
    V = []
    V.append(ano)
    for i in range(0, group_count):
        V.append(sm3_cf(V[i], B[i]))
    y = V[i+1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result

def sm3_kdf(z, klen):
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen/32)
    zin = [i for i in bytes.fromhex(z.decode('utf8'))]
    ha = ""
    for i in range(rcnt):
        msg = zin  + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
        ha = ha + sm3_hash(msg)
        ct += 1
    return ha[0: klen * 2]

from gmssl import sm3, func
import struct

def zh(x,y):
    return(((x << y) & 0xffffffff) | ((x >> (32 - y)) & 0xffffffff))

def padding(x):
    return(x + [(16 - len(x) % 16) for _ in range(16 - len(x) % 16)])

def hash2(old_hash, secret_len, append_m):
    vectors = []
    message = ""
    # 将old_hash分组，每组8个字节, 并转换为整数
    lenh1=len(old_hash)
    for r in range(0, lenh1, 8):
        vectors.append(int(old_hash[r:r + 8], 16))
    #将报文的哈希值以四个字节为一组分成八组转化为新的向量用来哈希附加的消息

    #对报文部分用字符‘1’来代替，然后在填充过后将附加的消息加到后面得到64字节的新报文
    if secret_len > 64:
        for i in range(0, int(secret_len / 64) * 64):
            message += '1'
    for i in range(0, secret_len % 64):
        message += '1'
    message = func.bytes_to_list(bytes(message, encoding='utf-8'))
    #将消息转为list元素方便填充
    message = padding(message)
    #填充1，0
    message.extend(func.bytes_to_list(bytes(append_m, encoding='utf-8')))
    #将附加的消息添加到已填充的报文后组成64字节
    return sm3_hash(message, vectors)
    #返回用新向量对新报文进行哈希的哈希值

def padding(msg):   #对报文进行填充
    mlen = len(msg)
    msg.append(0x80)   #先填充一个0x80
    mlen += 1
    tail = mlen % 64
    range_end = 56
    if tail > range_end:
        range_end = range_end + 64
    for i in range(tail, range_end):
        msg.append(0x00)   #再填充0x00，填到第56个
    bit_len = (mlen - 1) * 8
    msg.extend([int(x) for x in struct.pack('>q', bit_len)])
    for j in range(int((mlen - 1) / 64) * 64 + (mlen - 1) % 64, len(msg)):
        global pad
        pad.append(msg[j])
        global pad_str
        pad_str += str(hex(msg[j]))   #将报文转回16进制
    return msg
pad_str = ""
pad = []
baowen = str(random.randint(1000,9999))
#生成随机的报文
hash1 = sm3.sm3_hash(func.bytes_to_list(bytes(baowen, encoding='utf-8')))
#随机报文的哈希值
baowenchang = len(baowen)
#随机报文的长度
dif = "difficult"
# 附加的消息
hash2 = hash2(hash1, baowenchang, dif)
#用不同的向量加密附加的消息的哈希值
new_msg = func.bytes_to_list(bytes(baowen, encoding='utf-8'))
#将消息转为list元素方便填充
new_msg.extend(pad)
#填充1，0
new_msg.extend(func.bytes_to_list(bytes(dif, encoding='utf-8')))
#把附加的消息填到已填充的报文后凑成64字节
xinbaowen = baowen + pad_str + dif
#新的报文
hash3 = sm3.sm3_hash(new_msg)
#新的报文的哈希值
print("随机产生的报文为：")
print(baowen)
print("报文的哈希值为：")
print(hash1)
print("附加的消息为:")
print(dif)
print("将附加的消息补充到报文中组成新报文：")
print(xinbaowen)
print("以报文的哈希值作为向量对附加的消息进行哈希的值为：")
print(hash2)
print("新报文的哈希值为：")
print(hash3)
#比对hash2和hash3，一样说明长度扩展攻击成功
