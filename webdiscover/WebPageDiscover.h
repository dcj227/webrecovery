#pragma once

#include "stdafx.h"
#include <string>
#include <vector>

class CPcapFileHeader {			// Pcap�ļ����ļ�ͷ
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

class CPackHeader {			// Pcap�ļ������ݰ���ͷ
public:
	CPackHeader(void);
	~CPackHeader(void);

	timeval iTime_;
	//_Int32	iTimeSecond_;
	//_Int32	iTimeSS_;		// ΢��
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

/* 4�ֽڵ�IP��ַ */
class CIpAddress {
public:
    u_char byte1_;
    u_char byte2_;
    u_char byte3_;
    u_char byte4_;
};

/* IPv4 �ײ� */
class CIpHeader {
public:
    u_char		ver_ihl_;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char		tos_;            // ��������(Type of service) 
    u_short		tlen_;           // �ܳ�(Total length) 
    u_short		identification_; // ��ʶ(Identification)
    u_short		flags_fo_;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char		ttl_;            // ���ʱ��(Time to live)
    u_char		proto_;          // Э��(Protocol)
    u_short		crc_;            // �ײ�У���(Header checksum)
    CIpAddress  saddr_;			 // Դ��ַ(Source address)
    CIpAddress  daddr_;			 // Ŀ�ĵ�ַ(Destination address)
    u_int		op_pad_;         // ѡ�������(Option + Padding)
};

class CTcpHeader {
public:
	u_short	nSourPort_;			// Դ�˿ں�16bit
	u_short	nDestPort_;			// Ŀ�Ķ˿ں�16bit
	u_int	nSequNum_;			// ���к�32bit
	u_int	nAcknowledgeNum_;	// ȷ�Ϻ�32bit
	u_short	nHLenAndFlag_;		// ǰ4λ��TCPͷ���ȣ���6λ����������6λ����־λ 16bit
	u_short	nWindowSize_;		// ���ڴ�С16bit
	u_short	nCheckSum_;			// �����16bit
	u_short	nrgentPointer_;		// ��������ƫ����16bit
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