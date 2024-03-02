/*
以下代码实现了一个基本的 RTSP 服务器，用于处理 RTSP 协议的请求。

代码中的 createTcpSocket() 函数用于创建一个 TCP 套接字，并设置套接字选项 `SO_REUSEADDR`，以便在绑定之前可以重用地址。

bindSocketAddr() 函数用于将套接字绑定到指定的 IP 地址和端口号。

acceptClient() 函数用于接受客户端的连接，并获取客户端的 IP 地址和端口号。

handleCmd_OPTIONS()、handleCmd_DESCRIBE()、handleCmd_SETUP() 和 handleCmd_PLAY() 函数分别处理 RTSP 请求中的 OPTIONS、DESCRIBE、SETUP 和 PLAY 方法。这些函数根据请求的方法和参数生成相应的响应消息。

在 doClient() 函数中，通过循环接收客户端发送的 RTSP 请求，并根据请求的方法调用相应的处理函数生成响应消息，并将响应消息发送回客户端。

整个程序通过一个无限循环来监听客户端的连接，并为每个连接创建一个新的线程来处理客户端的请求。

需要注意的是，该代码在 Windows 环境下使用了 Winsock 库进行网络编程，因此需要包含相应的头文件，并链接对应的库文件。在 Linux 环境下，可以使用相应的 POSIX 函数来进行网络编程。

该代码只提供了基本的 RTSP 服务器功能，实际上，一个完整的 RTSP 服务器还需要处理更多的方法和参数，以及实现媒体流的传输和控制等功能。这只是一个简单的示例，实际应用中还需要根据需求进行相应的扩展和优化。
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include "rtp.h"
#include <thread>

#define AAC_FILE_NAME   "lion.aac" //AAC文件名 
#define H264_FILE_NAME   "lion.h264" // H264文件名
#define SERVER_PORT      8554 // 服务器端口号
#define BUF_MAX_SIZE     (1024*1024) // 缓冲区大小

static int createTcpSocket()
{
    int sockfd;
    int on = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return -1;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    return sockfd;
}

static int bindSocketAddr(int sockfd, const char* ip, int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr)) < 0)
        return -1;

    return 0;
}

static int acceptClient(int sockfd, char* ip, int* port)
{
    int clientfd;
    socklen_t len = 0;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    len = sizeof(addr);

    clientfd = accept(sockfd, (struct sockaddr*)&addr, &len);
    if (clientfd < 0)
        return -1;

    strcpy(ip, inet_ntoa(addr.sin_addr));
    *port = ntohs(addr.sin_port);

    return clientfd;
}

static inline int startCode3(char* buf) // 判断是否是start code 00 00 01（16进制 对应0x0 0x0 0x1）
{
    if (buf[0] == 0 && buf[1] == 0 && buf[2] == 1)
        return 1;
    else
        return 0;
}

static inline int startCode4(char* buf) // 判断是否是start code 00 00 00 01（16进制 对应0x0 0x0 0x0 0x1）
{
    if (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1)
        return 1;
    else
        return 0;
}

static char* findNextStartCode(char* buf, int len)
{
    int i;

    if (len < 3)
        return NULL;

    for (i = 0; i < len - 3; ++i)
    {
        if (startCode3(buf) || startCode4(buf)) // 找到下一个start code
            return buf;

        ++buf;
    }

    if (startCode3(buf)) // 找到下一个start code
        return buf;

    return NULL;
}

static int getFrameFromH264File(FILE* fp, char* frame, int size) { // 从H264文件中读取一帧数据
    int rSize, frameSize; // rSize：读取的大小 frameSize：帧的大小
    char* nextStartCode; // 下一个start code

    if (fp == NULL)
        return -1;

    rSize = fread(frame, 1, size, fp); // 从h264文件中读取一个size缓冲区大小的数据

    if (!startCode3(frame) && !startCode4(frame))
        return -1;

    nextStartCode = findNextStartCode(frame + 3, rSize - 3); // 找到下一个start code
    if (!nextStartCode)
    {
        //lseek(fd, 0, SEEK_SET);
        //frameSize = rSize;
        return -1;
    }
    else
    {
        frameSize = (nextStartCode - frame); // 帧的大小
        fseek(fp, frameSize - rSize, SEEK_CUR); // 移动文件指针

    }

    return frameSize;
}

struct AdtsHeader {
    unsigned int syncword;  // 12 bit 同步字 '1111 1111 1111'，说明一个ADTS帧的开始
    unsigned int id;        // 1 bit MPEG 标示符， 0 for MPEG-4，1 for MPEG-2
    unsigned int layer;     // 2 bit 总是'00'
    unsigned int protectionAbsent;  // 1 bit 1表示没有crc，0表示有crc
    unsigned int profile;           // 1 bit 表示使用哪个级别的AAC
    unsigned int samplingFreqIndex; // 4 bit 表示使用的采样频率
    unsigned int privateBit;        // 1 bit
    unsigned int channelCfg; // 3 bit 表示声道数
    unsigned int originalCopy;         // 1 bit
    unsigned int home;                  // 1 bit

    /*下面的为改变的参数即每一帧都不同*/
    unsigned int copyrightIdentificationBit;   // 1 bit
    unsigned int copyrightIdentificationStart; // 1 bit
    unsigned int aacFrameLength;               // 13 bit 一个ADTS帧的长度包括ADTS头和AAC原始流
    unsigned int adtsBufferFullness;           // 11 bit 0x7FF 说明是码率可变的码流

    /* number_of_raw_data_blocks_in_frame
     * 表示ADTS帧中有number_of_raw_data_blocks_in_frame + 1个AAC原始帧
     * 所以说number_of_raw_data_blocks_in_frame == 0
     * 表示说ADTS帧中有一个AAC数据块并不是说没有。(一个AAC原始帧包含一段时间内1024个采样及相关数据)
     */
    unsigned int numberOfRawDataBlockInFrame; // 2 bit
};

static int parseAdtsHeader(uint8_t* in, struct AdtsHeader* res) {
    static int frame_number = 0; // 帧数
    memset(res, 0, sizeof(*res)); // 初始化ADTS头

    if ((in[0] == 0xFF) && ((in[1] & 0xF0) == 0xF0)) // 0xFF是1111 1111，(in[1] & 0xF0) == 0xF0是1111 0000，也即满足1111 1111 1111 0000（0xFFF0）的条件，是ADTS帧的开始
    {
        res->id = ((uint8_t)in[1] & 0x08) >> 3; // 第二个字节与0x08与运算之后，右移三位，获得第13位bit对应的id值
        res->layer = ((uint8_t)in[1] & 0x06) >> 1; // 第二个字节与0x06与运算之后，右移一位，获得第14、15位bit对应的layer值
        res->protectionAbsent = (uint8_t)in[1] & 0x01; // 第二个字节与0x01与运算，获得第16位bit对应的protectionAbsent值
        res->profile = ((uint8_t)in[2] & 0xc0) >> 6; // 第三个字节与0xc0与运算之后，右移六位，获得第17、18位bit对应的profile值
        res->samplingFreqIndex = ((uint8_t)in[2] & 0x3c) >> 2; // 第三个字节与0x3c与运算之后，右移二位，获得第19、20、21、22位bit对应的samplingFreqIndex值
        res->privateBit = ((uint8_t)in[2] & 0x02) >> 1; // 第三个字节与0x02与运算之后，右移一位，获得第23位bit对应的privateBit值
        res->channelCfg = ((((uint8_t)in[2] & 0x01) << 2) | (((uint8_t)in[3] & 0xc0) >> 6)); // 第三个字节与0x01与运算之后，左移二位，与第四个字节与0xc0与运算之后，右移六位，获得第24、25、26位bit对应的channelCfg值
        res->originalCopy = ((uint8_t)in[3] & 0x20) >> 5; // 第四个字节与0x20与运算之后，右移五位，获得第27位bit对应的originalCopy值
        res->home = ((uint8_t)in[3] & 0x10) >> 4; // 第四个字节与0x10与运算之后，右移四位，获得第28位bit对应的home值
        res->copyrightIdentificationBit = ((uint8_t)in[3] & 0x08) >> 3; // 第四个字节与0x08与运算之后，右移三位，获得第29位bit对应的copyrightIdentificationBit值
        res->copyrightIdentificationStart = (uint8_t)in[3] & 0x04 >> 2; // 第四个字节与0x04与运算之后，右移二位，获得第30位bit对应的copyrightIdentificationStart值
        res->aacFrameLength = (((((uint8_t)in[3]) & 0x03) << 11) |
            (((uint8_t)in[4] & 0xFF) << 3) |
            ((uint8_t)in[5] & 0xE0) >> 5); // 第四个字节与0x03与运算之后，左移11位，第五个字节与0xFF与运算之后，左移3位，第六个字节与0xE0与运算之后，右移5位，获得第31-43位13个bit对应的aacFrameLength值
        res->adtsBufferFullness = (((uint8_t)in[5] & 0x1f) << 6 |
            ((uint8_t)in[6] & 0xfc) >> 2); // 第六个字节与0x1f与运算之后，左移6位，第七个字节与0xfc与运算之后，右移2位，获得第44-54位11个bit对应的adtsBufferFullness值
        res->numberOfRawDataBlockInFrame = ((uint8_t)in[6] & 0x03); // 第七个字节与0x03与运算之后，获得第55,56位两个bit对应的numberOfRawDataBlockInFrame值

        return 0;
    }
    else
    {
        printf("failed to parse adts header\n");
        return -1;
    }
}

static int rtpSendAACFrame(int clientSockfd,
    struct RtpPacket* rtpPacket, uint8_t* frame, uint32_t frameSize) { // 发送AAC帧数据
    //参考文档：https://blog.csdn.net/yangguoyu8023/article/details/106517251/
    int ret;

    rtpPacket->payload[0] = 0x00;
    rtpPacket->payload[1] = 0x10;
    rtpPacket->payload[2] = (frameSize & 0x1FE0) >> 5; // 高8位
    rtpPacket->payload[3] = (frameSize & 0x1F) << 3; // 低5位 合计为13位记录AAC帧长度

    memcpy(rtpPacket->payload + 4, frame, frameSize); // 复制AAC帧数据


    ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, frameSize + 4, 0x02); // 发送RTP包

    if (ret < 0)
    {
        printf("failed to send rtp packet\n");
        return -1;
    }

    rtpPacket->rtpHeader.seq++; // 序列号增加

    /*
     * 如果采样频率是44100
     * 一般AAC每个1024个采样为一帧
     * 所以一秒就有 44100 / 1024 = 43帧（FPS=43）
     * 时间增量就是 44100 / 43 = 1025
     * 一帧的时间为 1 / 43 = 23ms
     * 
     * 当采样率为48000时，时间增量为 960
     * 一帧的时间为 1 / 50 = 20ms
     */

    //rtpPacket->rtpHeader.timestamp += 1025;
    rtpPacket->rtpHeader.timestamp += 960; // 时间戳增加，每秒43帧

    return 0;
}


static int rtpSendH264Frame(int clientSockfd,
    struct RtpPacket* rtpPacket, char* frame, uint32_t frameSize)
{

    uint8_t naluType; // nalu第一个字节
    int sendByte = 0; // 发送的字节数
    int ret;

    naluType = frame[0];

    printf("%s frameSize=%d \n", __FUNCTION__, frameSize);

    if (frameSize <= RTP_MAX_PKT_SIZE) // nalu长度小于最大包场：单一NALU单元模式
    {

        //*   0 1 2 3 4 5 6 7 8 9
        //*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //*  |F|NRI|  Type   | a single NAL unit ... |
        //*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        memcpy(rtpPacket->payload, frame, frameSize); // 复制H264帧数据
        ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, frameSize, 0x00); // 发送RTP包
        if (ret < 0)
            return -1;

        rtpPacket->rtpHeader.seq++; // 序列号加1
        sendByte += ret; // 发送的字节数
        if ((naluType & 0x1F) == 7 || (naluType & 0x1F) == 8) // 如果是SPS、PPS就不需要加时间戳
        {
            goto out;
        }

    }
    else // nalu长度小于最大包：分片模式
    {

        //*  0                   1                   2
        //*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
        //* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //* | FU indicator  |   FU header   |   FU payload   ...  |
        //* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



        //*     FU Indicator
        //*    0 1 2 3 4 5 6 7
        //*   +-+-+-+-+-+-+-+-+
        //*   |F|NRI|  Type   |
        //*   +---------------+



        //*      FU Header
        //*    0 1 2 3 4 5 6 7
        //*   +-+-+-+-+-+-+-+-+
        //*   |S|E|R|  Type   |
        //*   +---------------+


        int pktNum = frameSize / RTP_MAX_PKT_SIZE;       // 有几个完整的包
        int remainPktSize = frameSize % RTP_MAX_PKT_SIZE; // 剩余不完整包的大小
        int i, pos = 1; // pos：指向nalu的位置

        // 发送完整的包
        for (i = 0; i < pktNum; i++)
        {
            rtpPacket->payload[0] = (naluType & 0x60) | 28; // 第一个字节 2、3位（NALU的NRI） 及 Type规范为28
            rtpPacket->payload[1] = naluType & 0x1F; // 第二个字节 后5位（NALU的Type）

            if (i == 0) //第一包数据
                rtpPacket->payload[1] |= 0x80; // start 也即S置1
            else if (remainPktSize == 0 && i == pktNum - 1) //最后一包数据
                rtpPacket->payload[1] |= 0x40; // end 也即E置1

            memcpy(rtpPacket->payload + 2, frame + pos, RTP_MAX_PKT_SIZE); // 拷贝nalu到rtp包的payload中
            ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, RTP_MAX_PKT_SIZE + 2, 0x00); // 发送rtp包
            if (ret < 0)
                return -1;

            rtpPacket->rtpHeader.seq++; // 序列号加1
            sendByte += ret;
            pos += RTP_MAX_PKT_SIZE; // 下一个包的位置
        }

        // 发送剩余的数据
        if (remainPktSize > 0) // 剩余不完整包的大小
        {
            rtpPacket->payload[0] = (naluType & 0x60) | 28;
            rtpPacket->payload[1] = naluType & 0x1F;
            rtpPacket->payload[1] |= 0x40; //end

            memcpy(rtpPacket->payload + 2, frame + pos, remainPktSize + 2);
            ret = rtpSendPacketOverTcp(clientSockfd, rtpPacket, remainPktSize + 2, 0x00);
            if (ret < 0)
                return -1;

            rtpPacket->rtpHeader.seq++;
            sendByte += ret;
        }
    }
out:
    return sendByte;

}

static int handleCmd_OPTIONS(char* result, int cseq)
{
    sprintf(result, "RTSP/1.0 200 OK\r\n"
        "CSeq: %d\r\n"
        "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
        "\r\n",
        cseq); // 根据请求的CSeq生成OPTIONS响应消息
    /*
    * sprintf 是一个 C 语言标准库函数，用于将格式化的数据写入一个字符串缓冲区。
    * int sprintf(char* str, const char* format, ...);
    *
    * 参数说明：
    * str：指向存储结果的字符串缓冲区。
    * format：格式化字符串，包含了要写入缓冲区的文本和格式控制符。
    * ...：可变数量的参数，根据格式化字符串中的格式控制符来提供相应类型的参数。
    *
    * 函数返回值：
    * sprintf 函数返回写入缓冲区的字符数，不包括字符串的结尾的空字符。如果写入过程发生错误，则返回负值。
    *
    * sprintf 函数将根据格式化字符串 format 中的格式控制符，将相应的数据转换为字符串，
    * 并按照格式化字符串的规定将其写入到指定的字符串缓冲区 str 中。通过使用不同的格式控制符，
    * 可以将整型、浮点型、字符型等不同类型的数据转换为字符串，并按照需要进行格式化输出。
    */
    return 0;
}

static int handleCmd_DESCRIBE(char* result, int cseq, char* url) // 构造 RTSP 中的 SDP（Session Description Protocol）和DESCRIBE请求的响应消息
{
    char sdp[500]; // SDP消息
    char localIp[100]; // 本地IP地址

    sscanf(url, "rtsp://%[^:]:", localIp); // 从URL中解析出本地IP地址

    sprintf(sdp, "v=0\r\n"
        "o=- 9%ld 1 IN IP4 %s\r\n"
        "t=0 0\r\n"
        "a=control:*\r\n"
        "m=video 0 RTP/AVP/TCP 96\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=control:track0\r\n" // track0 H264流

        "m=audio 1 RTP/AVP/TCP 97\r\n"
        "a=rtpmap:97 mpeg4-generic/44100/2\r\n"
        "a=fmtp:97 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1210;\r\n"
        "a=control:track1\r\n", // track1 AAC流

        time(NULL), localIp); // 构造SDP消息

    sprintf(result, "RTSP/1.0 200 OK\r\nCSeq: %d\r\n"
        "Content-Base: %s\r\n"
        "Content-type: application/sdp\r\n"
        "Content-length: %zu\r\n\r\n"
        "%s",
        cseq,
        url,
        strlen(sdp),
        sdp);

    return 0;
}

static int handleCmd_SETUP(char* result, int cseq)
{
    if (cseq == 3) {
        sprintf(result, "RTSP/1.0 200 OK\r\n"
            "CSeq: %d\r\n"
            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
            "Session: 66334873\r\n"
            "\r\n",
            cseq);
    }
    else if (cseq == 4) {
        sprintf(result, "RTSP/1.0 200 OK\r\n"
            "CSeq: %d\r\n"
            "Transport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n"
            "Session: 66334873\r\n"
            "\r\n",
            cseq);
    }


    return 0;
}

static int handleCmd_PLAY(char* result, int cseq)
{
    sprintf(result, "RTSP/1.0 200 OK\r\n"
        "CSeq: %d\r\n"
        "Range: npt=0.000-\r\n"
        "Session: 66334873; timeout=10\r\n\r\n",
        cseq);

    return 0;
}

static void doClient(int clientSockfd, const char* clientIP, int clientPort) {

    char method[40]; // 请求方法
    char url[100]; // 请求URL
    char version[40]; // RTSP版本
    int CSeq; // RTSP请求序列号

    char* rBuf = (char*)malloc(BUF_MAX_SIZE); // 接收缓冲区
    char* sBuf = (char*)malloc(BUF_MAX_SIZE); // 发送缓冲区

    while (true) {
        int recvLen; // 接收到的数据长度

        recvLen = recv(clientSockfd, rBuf, BUF_MAX_SIZE, 0); // 接收客户端发送的RTSP请求
        if (recvLen <= 0) {
            break;
        }

        rBuf[recvLen] = '\0';
        printf("接收请求 rBuf = %s \n", rBuf);

        const char* sep = "\n";

        char* line = strtok(rBuf, sep); // 分割请求消息
        /*
        * strtok 是一个 C 语言标准库函数，用于将一个字符串按照指定的分隔符拆分成多个子字符串。
        * char* strtok(char* str, const char* delim);
        * str：要拆分的字符串。
        * delim：分隔符字符串，用于指定拆分子字符串的标志。
        * 第一次调用时，返回 str 中第一个被拆分出来的子字符串的指针。
        * 后续调用时，返回 NULL 或者下一个被拆分出来的子字符串的指针。
        */
        while (line) {
            if (strstr(line, "OPTIONS") ||
                strstr(line, "DESCRIBE") ||
                strstr(line, "SETUP") ||
                strstr(line, "PLAY")) { // 判断字符串中是否包含指定的子字符串
                /*
                * strstr 是一个 C 语言标准库函数，用于在一个字符串中查找子字符串的出现位置。
                *
                * char* strstr(const char* str1, const char* str2);
                * str1：要搜索的字符串。
                * str2：要查找的子字符串。
                *
                * 如果 str2 是 str1 的子字符串，则返回指向 str1 中第一次出现 str2 的位置的指针。
                * 如果未找到 str2，则返回 NULL。
                */
                if (sscanf(line, "%s %s %s\r\n", method, url, version) != 3) {// 从字符串中按照指定的格式提取数据
                    /*
                    * sscanf 是一个 C 语言标准库函数，用于从一个字符串中按照指定的格式提取数据。
                    * int sscanf(const char* str, const char* format, ...);
                    * 参数说明：
                    * str：要解析的字符串。
                    * format：格式字符串，用于指定要提取的数据的格式。
                    * ...：可变参数，用于接收提取出的数据。
                    *
                    * 函数返回值：
                    * 成功解析并提取数据的个数。
                    * 如果发生解析错误或者没有提取到任何数据，则返回值为负数。
                    */
                    // error
                }
            }
            else if (strstr(line, "CSeq")) { // 判断字符串中是否包含"CSeq"
                if (sscanf(line, "CSeq: %d\r\n", &CSeq) != 1) { // 从字符串中按照指定的格式提取数据
                    // error
                }
            }
            else if (!strncmp(line, "Transport:", strlen("Transport:"))) { // 判断字符串是否以"Transport:"开头
                // Transport: RTP/AVP/UDP;unicast;client_port=13358-13359
                // Transport: RTP/AVP;unicast;client_port=13358-13359

                if (sscanf(line, "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n") != 0) { // 从字符串中按照指定的格式提取客户端的RTP端口和RTCP端口
                    // error
                    printf("parse Transport error \n");
                }
            }
            line = strtok(NULL, sep); // 继续分割字符串
        }

        if (!strcmp(method, "OPTIONS")) {
            if (handleCmd_OPTIONS(sBuf, CSeq)) // 处理OPTIONS请求
            {
                printf("failed to handle options\n");
                break;
            }
        }
        else if (!strcmp(method, "DESCRIBE")) { // 处理DESCRIBE请求
            if (handleCmd_DESCRIBE(sBuf, CSeq, url))
            {
                printf("failed to handle describe\n");
                break;
            }
        }
        else if (!strcmp(method, "SETUP")) { // 处理SETUP请求
            if (handleCmd_SETUP(sBuf, CSeq))
            {
                printf("failed to handle setup\n");
                break;
            }
        }
        else if (!strcmp(method, "PLAY")) { // 处理PLAY请求
            if (handleCmd_PLAY(sBuf, CSeq))
            {
                printf("failed to handle play\n");
                break;
            }
        }
        else {
            printf("未定义的method = %s \n", method);
            break;
        }
        printf("响应 sBuf = %s \n", sBuf);

        send(clientSockfd, sBuf, strlen(sBuf), 0); // 发送RTSP响应消息


        //开始播放，发送RTP包
        if (!strcmp(method, "PLAY")) {
            // 发送H264的RTP包
            std::thread t1([&]() {

                int frameSize, startCode;
                char* frame = (char*)malloc(500000); // 500k 视频码流（如果使用更高分辨率视频这个码率其实不够）
                struct RtpPacket* rtpPacket = (struct RtpPacket*)malloc(500000); // RTP包
                FILE* fp = fopen(H264_FILE_NAME, "rb");
                if (!fp) {
                    printf("读取 %s 失败\n", H264_FILE_NAME);
                    return;
                }
                rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VESION, RTP_PAYLOAD_TYPE_H264, 0,
                    0, 0, 0x88923423);  // 初始化rtp包头 ssrc ：0x88923423 确保每个rtp包的ssrc都是一样的

                printf("start play\n");

                while (true) {
                    frameSize = getFrameFromH264File(fp, frame, 500000); // 从H264文件中读取一帧数据
                    if (frameSize < 0)
                    {
                        printf("读取%s结束,frameSize=%d \n", H264_FILE_NAME, frameSize);
                        break;
                    }

                    if (startCode3(frame)) // 判断是否为3字节起始码
                        startCode = 3;
                    else
                        startCode = 4;

                    frameSize -= startCode;
                    rtpSendH264Frame(clientSockfd, rtpPacket, frame + startCode, frameSize); // 发送H264帧数据

                    rtpPacket->rtpHeader.timestamp += 90000 / 24; // 时间戳增加 90000为h264定义的时间基准 25为帧率

                    //Sleep(40);//->30,20,
                    Sleep(40);
                    //usleep(40000);//1000/25 * 1000
                }
                free(frame);
                free(rtpPacket);

                });
            // 发送AAC的RTP包
            std::thread t2([&]() { 
                struct AdtsHeader adtsHeader;
                struct RtpPacket* rtpPacket;
                uint8_t* frame;
                int ret;

                FILE* fp = fopen(AAC_FILE_NAME, "rb");
                if (!fp) {
                    printf("读取 %s 失败\n", AAC_FILE_NAME);
                    return;
                }

                frame = (uint8_t*)malloc(5000); // AAC帧数据
                rtpPacket = (struct RtpPacket*)malloc(5000); // RTP包

                rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VESION, RTP_PAYLOAD_TYPE_AAC, 1, 0, 0, 0x32411); // 初始化RTP头

                while (true)
                {
                    ret = fread(frame, 1, 7, fp); // 从AAC文件中读取ADTS头
                    if (ret <= 0)
                    {
                        printf("fread err\n");
                        break;
                    }
                    printf("fread ret=%d \n", ret);

                    if (parseAdtsHeader(frame, &adtsHeader) < 0) // 解析ADTS头
                    {
                        printf("parseAdtsHeader err\n");
                        break;
                    }
                    ret = fread(frame, 1, adtsHeader.aacFrameLength - 7, fp); // 从AAC文件中读取AAC帧数据
                    if (ret <= 0)
                    {
                        printf("fread err\n");
                        break;
                    }

                    rtpSendAACFrame(clientSockfd,
                        rtpPacket, frame, adtsHeader.aacFrameLength - 7); // 发送AAC帧数据


                    Sleep(1);
                    //Sleep(23);
                    // usleep(23223);//1000/43.06 * 1000
                }

                free(frame);
                free(rtpPacket);
                });

            t1.join();
            t2.join();

            break;
        }

        memset(method, 0, sizeof(method) / sizeof(char));
        memset(url, 0, sizeof(url) / sizeof(char));
        CSeq = 0;


    }

    closesocket(clientSockfd);
    free(rBuf);
    free(sBuf);

}

int main(int argc, char* argv[])
{
    WSADATA wsaData;
    //启动socket
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("PC Server Socket Start Up Error \n");
        return -1;
    }

    int serverSockfd;
    serverSockfd = createTcpSocket();
    if (serverSockfd < 0)
    {
        WSACleanup();
        printf("failed to create tcp socket\n");
        return -1;
    }

    if (bindSocketAddr(serverSockfd, "0.0.0.0", SERVER_PORT) < 0)
    {
        printf("failed to bind addr\n");
        return -1;
    }

    if (listen(serverSockfd, 10) < 0)
    {
        printf("failed to listen\n");
        return -1;
    }

    printf("%s rtsp://127.0.0.1:%d\n", __FILE__, SERVER_PORT);

    while (true) {
        int clientSockfd;
        char clientIp[40];
        int clientPort;

        clientSockfd = acceptClient(serverSockfd, clientIp, &clientPort);
        if (clientSockfd < 0)
        {
            printf("failed to accept client\n");
            return -1;
        }

        printf("accept client;client ip:%s,client port:%d\n", clientIp, clientPort);

        doClient(clientSockfd, clientIp, clientPort);
    }
    closesocket(serverSockfd);
    WSACleanup();
    return 0;
}
