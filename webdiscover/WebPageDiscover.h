#pragma once

#include "stdafx.h"
#include <string>
#include <vector>

class CPcapFileHeader {			// Pcap文件的文件头
public:
	CPcapFileHeader(void);
	~CPcapFileHeader(void);

	_Int32	iMagic_;
	_Int16	iMaVersion_;
	_Int16	iMiVersion_;
	_Int32	iTimezone_;
	_Int32	iSigFlags_;
	_Int32	iSnapLen_;
	_Int32	iLinkType_;
};

class CPackHeader {			// Pcap文件中数据包的头
public:
	CPackHeader(void);
	~CPackHeader(void);

	timeval iTime_;
	//_Int32	iTimeSecond_;
	//_Int32	iTimeSS_;		// 微秒
	_Int32	iCaptureLength_;
	_Int32	iActualLength_;
};

class CPcapPackage {
public:
	CPcapPackage(const CPackHeader* header, const _Int8* data);
	~CPcapPackage(void);

	CPackHeader* GetHeader();
	_Int8* GetData();

private:
	CPackHeader* pack_header_;
	_Int8*		 data_;
};

/* 4字节的IP地址 */
class CIpAddress {
public:
    u_char byte1_;
    u_char byte2_;
    u_char byte3_;
    u_char byte4_;
};

/* IPv4 首部 */
class CIpHeader {
public:
    u_char		ver_ihl_;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char		tos_;            // 服务类型(Type of service) 
    u_short		tlen_;           // 总长(Total length) 
    u_short		identification_; // 标识(Identification)
    u_short		flags_fo_;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char		ttl_;            // 存活时间(Time to live)
    u_char		proto_;          // 协议(Protocol)
    u_short		crc_;            // 首部校验和(Header checksum)
    CIpAddress  saddr_;			 // 源地址(Source address)
    CIpAddress  daddr_;			 // 目的地址(Destination address)
    u_int		op_pad_;         // 选项与填充(Option + Padding)
};

class CTcpHeader {
public:
	u_short	nSourPort_;			// 源端口号16bit
	u_short	nDestPort_;			// 目的端口号16bit
	u_int	nSequNum_;			// 序列号32bit
	u_int	nAcknowledgeNum_;	// 确认号32bit
	u_short	nHLenAndFlag_;		// 前4位：TCP头长度；中6位：保留；后6位：标志位 16bit
	u_short	nWindowSize_;		// 窗口大小16bit
	u_short	nCheckSum_;			// 检验和16bit
	u_short	nrgentPointer_;		// 紧急数据偏移量16bit
};

class CFileAttribute {
public:
	std::string full_file_name_;
	std::string data_;
	std::string encoding_;
};


class CWebPageDiscover {
public:
	CWebPageDiscover(void);
	~CWebPageDiscover(void);

	error_no LoadPacpFile(char* file_name);
	error_no FitlerWithProtocolPort();
	error_no SeperateBySession();
	error_no OutputSessionToPcap(const char* file_path);
	error_no SeperateByRequest();
	error_no OutputRequetToPcap(const char* file_path);
	error_no GenerateWebFile(const char* file_path);
	//error_no SortPackageWithSyn();
	error_no GenerateWebFileStep(const char* file_path, std::vector<CPcapPackage*>* packs);

private:
	CPcapFileHeader*	file_header_;
	std::vector<CPcapPackage*>* data_packages_;
	std::vector<std::vector<CPcapPackage*>*>* sessions_;
	std::vector<std::vector<CPcapPackage*>*>* requests_;
	std::vector<CFileAttribute*>* files_;
};