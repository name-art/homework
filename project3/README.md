# 项目名称：SM3长度扩展攻击
## 项目简介：对SM3使用长度扩展攻击
### 完成人：徐骏骐
### 代码说明：
长度扩展攻击的流程为：先随机生成一个报文（即未知报文），然后使用SM3算出报文的哈希值hash1，
再将哈希值hash1按照四字节为一组分成八组，将其作为新的向量来加密附加的消息，得到哈希值hash2，
最后将报文长度对应的代替串（已知报文长度，将与报文长度对应位置的报文写为一串‘1’，也可以是其他字符）+填充+附加
的消息组成新的报文，将其进行哈希，得到哈希值3，对比哈希值2和哈希值3，若相等则长度扩展攻击成功。
由于需要用第一个哈希值对应的向量来加密附加的消息，所以需要添加一个可以自主设定向量的SM3函数，
其向量为将hash1分为八组后的每一组串的转化。在填充时需要注意类型的转换。
### 运行指导：
使用IDLE运行，从输出框可以得知随机产生的报文、报文的哈希值hash1、附加的消息
（例子中使用的是‘difficult’）、使用特殊向量的SM3加密附加消息的哈希值hash2、
填充后的新报文和其对应的哈希值hash3，若没有出错，则hash2和hash3应该是相同的，这表明攻击成功。
### 运行截图在文件夹中
