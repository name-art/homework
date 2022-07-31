import math
from random import randint
from gmssl import sm3,func

#方程y2=x3+ax+b

p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


def gcd(p,q): #最大公因子
    if q>p:
        p,q=q,p
    while(q!=0):
        p,q=q,p%q
    return p

def xcd(p,n):  #求模逆
    s=[1,0]
    t=[0,1]
    r=[n,p]
    rr=n%p
    while(rr!=0):
        q=r[0]//r[1]
        r.append(rr)
        s.append(s[0]-q*s[1])
        t.append(t[0]-q*t[1])
        r.pop(0);s.pop(0);t.pop(0)
        rr=r[0]%r[1]
    return t[1]

def addit(x1,y1,x2,y2,a,p): #两点相加
    if(x1==x2 and y1==p-y2):
        return false
    elif(x1==x2):
        lmd=(((3*x1*x1+a)%p)*xcd(2*y1,p))%p
    else:
        lmd=((y2-y1)%p*xcd((x2-x1)%p,p))%p
    x3=(lmd*lmd-x1-x2)%p
    y3=(lmd*(x1-x3)-y1)%p
    return x3,y3
        
    
def multipoint(x,y,k,a,p):    #计算椭圆曲线点
    k=bin(k)[2:]      
    xp,yp=x,y
    for i in range(1,len(k)):
        xp,yp=addit(xp,yp,xp,yp,a,p)
        if k[i]=='1':
            xp,yp=addit(xp,yp,x,y,a,p)
    return xp,yp


def KDF(st,klen):    #密钥生成函数
    ct=1
    k=''
    for i in range(math.ceil(klen/256)):
        tp=hex(int(st+'{:032b}'.format(ct),2))[2:]
        tp1=sm3.sm3_hash(func.bytes_to_list(tp.encode()))
        k+=bin(int(tp1,16))[2:].rjust(256,'0')
        ct+=1
    return k[:klen]
    
def encrypt(dB,xB,yB,message):   #加密
    tp=bin(int(message.encode().hex(),16))[2:]
    tpp=4-(len(tp)%4)       #填充
    m=tpp*'0'+tp
    klen=len(m)
    plen=len(hex(p)[2:])
    while True:    #计算k=hash（d+hash（m））
        hm=sm3.sm3_hash(func.bytes_to_list(bytes(str(m), encoding='utf-8'))) #hash(m)
        ihm=int(hm,16)     #hash(m)转为int型
        er=dB+ihm        #将dB与hash(m)相加
        k1=sm3.sm3_hash(func.bytes_to_list(bytes(str(er), encoding='utf-8')))#hash(d+hash(m))
        k=int(k1,16)     #转换为int型
        x1,y1=multipoint(GX,GY,k,a,p)
        x2,y2=multipoint(xB,yB,k,a,p)#计算k[PB]
        x2='{:0256b}'.format(x2)
        y2='{:0256b}'.format(y2)
        t=KDF(x2+y2,klen)
        if t!=0:
            break
    x1=hex(x1)[2:].rjust(plen,'0')   #点转化为比特串
    y1=hex(y1)[2:].rjust(plen,'0')
    C1='04'+x1+y1
    C2=hex(int(m,2)^int(t,2))[2:].rjust(math.ceil(klen/4),'0') #填充
    temp=hex(int(x2+m+y2,2))[2:].encode()#转为字节串
    C3=sm3.sm3_hash(func.bytes_to_list(temp))
    return C1,C2,C3     #返回密文



def decrypt(dB,c,a,b,p):   #解密
    plen=len(hex(p)[2:])
    c1=c[:(2*plen+2)][2:]
    c2=c[(2*plen+2):-64]
    c3=c[-64:]
    klen=(len(c)-2-plen*2-64)*4
    x1=int(c1[:plen],16)
    y1=int(c1[plen:],16)
    if pow(y1,2,p)!=(pow(x1,3,p)+a*x1+b)%p:
        print('aa')
        return False
    x2,y2=multipoint(x1,y1,dB,a,p)
    x2='{:0256b}'.format(x2)
    y2='{:0256b}'.format(y2)
    t=KDF(x2+y2,klen)
    if t==0:
        print('aa')
        return False
    m=bin(int(c2,16)^int(t,2))[2:].rjust(klen,'0')
    temp=hex(int(x2+m+y2,2))[2:].encode()
    u=sm3.sm3_hash(func.bytes_to_list(temp))
    if u!=c3:
        print('ab')
        return False
    m=hex(int(m,2))[2:]
    m=str(bytes.fromhex(m))
    return m

dB=randint(1,n-1)
xB,yB=multipoint(GX,GY,dB,a,p)
m='sm2dejiajiemi'#设明文为‘sm2dejiajiemi’
print("明文:",m)
c1,c2,c3=encrypt(dB,xB,yB,m)   #加密
c=c1+c2+c3
print("密文:",c)
cc=decrypt(dB,c,a,b,p)         #解密
print("明文：",cc)
