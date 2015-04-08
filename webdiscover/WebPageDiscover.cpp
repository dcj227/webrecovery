#include "stdafx.h"
#include <memory>
#include <direct.h>
#include "gzip.h"
#include "GLogHelper.h"
#include "WebPageDiscover.h"

const int kLinkLayerHeaderLength = 14;
const int kTcpProtocol = 6;

class CIpPortPair {
public:
	CIpPortPair(void);
	CIpPortPair(const CIpAddress &src_ip, const _Int16 src_port,
		const CIpAddress &dest_ip, const _Int16 dest_port);
	void Set(const CIpAddress &src_ip, const _Int16 src_port,
		const CIpAddress &dest_ip, const _Int16 dest_port);
	bool IsPair(const CIpPortPair &ipport);

	CIpAddress	src_ip_;
	u_short		src_port_;
	CIpAddress	dest_ip_;
	u_short		dest_port_;
};

CIpPortPair::CIpPortPair(void) {

}

CIpPortPair::CIpPortPair(const CIpAddress &src_ip, const _Int16 src_port,
					   const CIpAddress &dest_ip, const _Int16 dest_port) {
	Set(src_ip, src_port, dest_ip, dest_port);
}

void CIpPortPair::Set(const CIpAddress &src_ip, const _Int16 src_port,
					  const CIpAddress &dest_ip, const _Int16 dest_port) {
	src_ip_ = src_ip;
	src_port_ = src_port;
	dest_ip_ = dest_ip;
	dest_port_ = dest_port;
	assert(memcmp((void*)&src_ip_, (void*)&dest_ip_, sizeof(CIpAddress)) != 0);
	assert(src_port_ != dest_port_);
}

bool CIpPortPair::IsPair(const CIpPortPair &ipport) {
	if ((int&)src_ip_ == (int&)ipport.src_ip_ && (int&)dest_ip_ == (int&)ipport.dest_ip_ &&
		src_port_ == ipport.src_port_ && dest_port_ == ipport.dest_port_) {
			return true;
	} else if ((int&)src_ip_ == (int&)ipport.dest_ip_ && (int&)dest_ip_ == (int&)ipport.src_ip_ &&
		src_port_ == ipport.dest_port_ && dest_port_ == ipport.src_port_) {
			return true;
	} else {
		return false;
	}
}



CPcapFileHeader::CPcapFileHeader(void) {
}

CPcapFileHeader::~CPcapFileHeader(void) {

}

CPackHeader::CPackHeader(void) {

}

CPackHeader::~CPackHeader(void) {

}

CPcapPackage::CPcapPackage(const CPackHeader* header, const _Int8* data) {
	assert(header != NULL);
	pack_header_ = new CPackHeader(*header);
	assert(pack_header_ != NULL);
	data_ = new _Int8[pack_header_->iActualLength_];
	assert(data_ != NULL);
	memcpy((void*)data_, (void*)data, pack_header_->iActualLength_);
}

CPcapPackage::~CPcapPackage(void) {
	if (data_) {
		delete [] data_;
		data_ = NULL;
	}
	if (pack_header_) {
		delete pack_header_;
		pack_header_ = NULL;
	}
}

CPackHeader* CPcapPackage::GetHeader() {
	return pack_header_;
}

_Int8* CPcapPackage::GetData() {
	return data_;
}



CWebPageDiscover::CWebPageDiscover(void)
{
	file_header_ = new CPcapFileHeader;
	data_packages_ = new std::vector<CPcapPackage*>;
	sessions_ = new std::vector<std::vector<CPcapPackage*>*>;
	requests_ = new std::vector<std::vector<CPcapPackage*>*>;
	files_ = new std::vector<CFileAttribute*>;
}

CWebPageDiscover::~CWebPageDiscover(void)
{
	if (files_) {
		for (size_t i =0; i < files_->size(); i++) {
			if ((*files_)[i]) {
				delete (*files_)[i];
				(*files_)[i] = NULL;
			}
		}
		delete files_;
		files_ = NULL;
	}

	if (requests_) {		// 和 data_packages_ 共享内存，所以在这里不需要 delete 具体数据
		for (size_t i = 0; i < requests_->size(); i++) {
			if ((*requests_)[i]) {
				delete (*requests_)[i];
				(*requests_)[i] = NULL;
			}
		}
		delete requests_;
		requests_ = NULL;
	}

	if (sessions_) {		// 和 data_packages_ 共享内存，所以在这里不需要 delete 具体数据。
		for (size_t i = 0; i < sessions_->size(); i++) {
			if ((*sessions_)[i]) {
				delete (*sessions_)[i];
				(*sessions_)[i] = NULL;
			}
		}
		delete sessions_;
		sessions_ = NULL;
	}

	if (data_packages_) {
		for (size_t i = 0; i < data_packages_->size(); i++) {
			if ((*data_packages_)[i]) {
				delete (*data_packages_)[i];
				(*data_packages_)[i] = NULL;
			}
		}
		delete data_packages_;
		data_packages_ = NULL;
	}
	if (file_header_) {
		delete file_header_;
		file_header_ = NULL;
	}
}

error_no CWebPageDiscover::LoadPacpFile(char* file_name) {
	long file_len = 0;
	_Int8* buffer = NULL;
	FILE* fp = fopen(file_name, "rb");
	if (fp == NULL) {
		LOG(GERROR) << "open pcap file error.";
		return FILE_ERROR;
	}

	fseek(fp, 0, SEEK_END);
	file_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//std::unique_ptr<_Int8> buffer(new _Int8[file_len]);
	buffer = new _Int8[file_len];
	fread( (void*)buffer, 1, file_len, fp);
	fclose(fp);

	memcpy( (void*)file_header_, (void*)buffer, sizeof(CPcapFileHeader));

	_Int8* p = NULL;
	for (p = buffer + sizeof(CPcapFileHeader); p < buffer + file_len; ) {
		CPcapPackage* pack = new CPcapPackage( (CPackHeader*)p, (_Int8*)(p + sizeof(CPackHeader)) );
		data_packages_->push_back(pack);
		p = p + sizeof(CPackHeader) + pack->GetHeader()->iActualLength_;
	}
	LOG_IF(GERROR, p != buffer + file_len) << "pcap文件不完整。";
	//LOG(INFO) << "load file done.";
	return SUCCESS;
}

error_no CWebPageDiscover::FitlerWithProtocolPort() {
	CIpHeader ip_header;
	CTcpHeader tcp_header;
	for (auto it = data_packages_->begin(); it != data_packages_->end(); ) {
		memcpy(&ip_header, (*it)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
		int header_len = (ip_header.ver_ihl_ & 0x0F) * 4;
		memcpy(&tcp_header, (*it)->GetData() + kLinkLayerHeaderLength + header_len, sizeof(CTcpHeader));

		if ((ip_header.proto_ != kTcpProtocol) || 
			(ntohs(tcp_header.nDestPort_) != 80 && ntohs(tcp_header.nSourPort_) != 80)) {
			if ((*it)) {
				delete (*it);
				(*it) = NULL;
			}
			it = data_packages_->erase(it);
		} else {
			++it;
		}
	}
	LOG(INFO) << "filter with protocol success.";
	return SUCCESS;
}

error_no CWebPageDiscover::SeperateBySession() {
	CIpPortPair pair1, pair2;
	CIpHeader ip_header;
	CTcpHeader tcp_header;
	for (auto it = data_packages_->begin(); it != data_packages_->end(); ++it) {
		memcpy(&ip_header, (*it)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
		int header_len = (ip_header.ver_ihl_ & 0x0F) * 4;
		memcpy(&tcp_header, (*it)->GetData() + kLinkLayerHeaderLength + header_len, sizeof(CTcpHeader));

		memcpy(&pair1.src_ip_, &ip_header.saddr_, sizeof(CIpAddress));
		memcpy(&pair1.dest_ip_, &ip_header.daddr_, sizeof(CIpAddress));
		memcpy(&pair1.src_port_,  &tcp_header.nSourPort_, sizeof(u_short));
		memcpy(&pair1.dest_port_, &tcp_header.nDestPort_, sizeof(u_short));

		auto it2 = sessions_->begin();
		for ( ; it2 != sessions_->end(); ++it2) {
			memcpy(&ip_header, ((*(*it2))[0])->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
			int header_len = (ip_header.ver_ihl_ & 0x0F) * 4;
			memcpy(&tcp_header, ((*(*it2))[0])->GetData() + kLinkLayerHeaderLength + header_len, sizeof(CTcpHeader));

			memcpy(&pair2.src_ip_, &ip_header.saddr_, sizeof(CIpAddress));
			memcpy(&pair2.dest_ip_, &ip_header.daddr_, sizeof(CIpAddress));
			memcpy(&pair2.src_port_,  &tcp_header.nSourPort_, sizeof(u_short));
			memcpy(&pair2.dest_port_, &tcp_header.nDestPort_, sizeof(u_short));

			if (pair1.IsPair(pair2) == true) {
				(*it2)->push_back((*it));
				break;
			}
		}

		if (it2 == sessions_->end()) {
			std::vector<CPcapPackage*>* session = new std::vector<CPcapPackage*>;
			session->push_back((*it));
			sessions_->push_back(session);
		}
	}
	return SUCCESS;
}

error_no CWebPageDiscover::OutputSessionToPcap(const char* file_path) {
	std::string file_name;
	std::string buffer;
	int i = 0;
	for (auto it1 = sessions_->begin(); it1 != sessions_->end(); ++it1) {
		buffer.clear();
		buffer.append((char*)file_header_, sizeof(CPcapFileHeader));
		for (auto it2 = (*it1)->begin(); it2 != (*it1)->end(); ++it2) {
			buffer.append((char*)(*it2)->GetHeader(), sizeof(CPackHeader));
			buffer.append((char*)(*it2)->GetData(), (*it2)->GetHeader()->iActualLength_);
		}
		file_name = file_path;
		char index[16] = {0};
		file_name.append(_itoa(i++, index, 10));
		file_name.append(".pcap");
		FILE* fp = fopen(file_name.c_str(), "wb");
		fwrite(buffer.c_str(), 1, buffer.size(), fp);
		fclose(fp);
	}
	return SUCCESS;
}

error_no CWebPageDiscover::SeperateByRequest() {
	CIpHeader ip_header;
	CTcpHeader tcp_header;
	for (auto it = sessions_->begin(); it != sessions_->end(); ++it) {
		int state = 0;
		std::vector<CPcapPackage*>* ptr = NULL;
		for (auto it2 = (*it)->begin(); it2 != (*it)->end(); ++it2) {
			memcpy(&ip_header, (*it2)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
			int ip_header_len = (ip_header.ver_ihl_ & 0x0F) * 4;
			memcpy(&tcp_header, (*it2)->GetData() + kLinkLayerHeaderLength + ip_header_len, sizeof(CTcpHeader));
			unsigned int tcp_header_len = ((ntohs(tcp_header.nHLenAndFlag_) & 0xF000) >> 12) * 4;
			char* data = (*it2)->GetData() + kLinkLayerHeaderLength + ip_header_len + tcp_header_len;

			if (data[0] =='G' && data[1] == 'E' && data[2] == 'T') {
				ptr = new std::vector<CPcapPackage*>;
				requests_->push_back(ptr);
				state = 1;
			}
			if (state == 1) {
				ptr->push_back(*it2);
			}
		}
	}
	return SUCCESS;
}

error_no CWebPageDiscover::OutputRequetToPcap(const char* file_path) {
	std::string file_name;
	std::string buffer;
	int i = 0;
	for (auto it1 = requests_->begin(); it1 != requests_->end(); ++it1) {
		buffer.clear();
		buffer.append((char*)file_header_, sizeof(CPcapFileHeader));
		for (auto it2 = (*it1)->begin(); it2 != (*it1)->end(); ++it2) {
			buffer.append((char*)(*it2)->GetHeader(), sizeof(CPackHeader));
			buffer.append((char*)(*it2)->GetData(), (*it2)->GetHeader()->iActualLength_);
		}
		file_name = file_path;
		char index[16] = {0};
		file_name.append(_itoa(i++, index, 10));
		file_name.append(".pcap");
		FILE* fp = fopen(file_name.c_str(), "wb");
		fwrite(buffer.c_str(), 1, buffer.size(), fp);
		fclose(fp);
	}
	return SUCCESS;
}

error_no CWebPageDiscover::GenerateWebFile(const char* file_path) {
	error_no err_t;
	for (auto it = requests_->begin(); it != requests_->end(); ++it) {
		err_t = GenerateWebFileStep(file_path, (*it));
		LOG_IF(GERROR, err_t != SUCCESS) << "Generate web file error.";
	}

	// gzdecompress
	char* temp = new char[1024 * 1024];
	memset(temp, 0, 1024 * 1024);
	assert(temp);

	for (auto it = files_->begin(); it != files_->end(); ++it) {
		CString path(const_cast<char*>((*it)->full_file_name_.substr(0, (*it)->full_file_name_.rfind('\\') + 1).c_str()));
		if(!PathFileExists(path)) {
			_mkdir(CT2A(path));
		}
		FILE* fp = fopen((*it)->full_file_name_.c_str(), "wb");
		if (fp == NULL) {
			continue;
		}

		if ((*it)->encoding_.find("gzip") != std::string::npos) {
			(*it)->data_.erase(0, 6);
			int ret = inflate_read(const_cast<char*>((*it)->data_.c_str()),
				(*it)->data_.size(), &temp, 1);
			if (ret == Z_OK)
				fwrite(temp, 1, strlen(temp), fp);
		} else {
			fwrite((*it)->data_.c_str(), 1, (*it)->data_.size(), fp);
		}
		fclose(fp);
	}

	return SUCCESS;
}

error_no CWebPageDiscover::GenerateWebFileStep(const char* file_path, std::vector<CPcapPackage*>* packs) {
	CIpHeader ip_header;
	CTcpHeader tcp_header;
	std::string full_file_name;
	std::string director;
	std::string file_name;
	std::string encoding;
	int file_length = -1;
	std::string buffer;
	CIpPortPair pair1, pair2;
	std::vector<CPcapPackage*> send_obj, recv_obj;
	CIpAddress local_ip;
	int ip_header_len = 0, tcp_header_len = 0;
	char* data = NULL;

	auto it = packs->begin();
	memcpy(&ip_header, (*it)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
	(int&)local_ip = (int&)ip_header.saddr_;

	// 分成两个 vector
	for (it = packs->begin(); it != packs->end(); ++it) {
		memcpy(&ip_header, (*it)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
		if ((int&)local_ip == (int&)ip_header.saddr_) {
			send_obj.push_back(*it);
		} else {
			recv_obj.push_back(*it);
		}
	}

	// 得到文件名字
	auto it_send = send_obj.begin();
	memcpy(&ip_header, (*it_send)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
	ip_header_len = (ip_header.ver_ihl_ & 0x0F) * 4;
	memcpy(&tcp_header, (*it_send)->GetData() + kLinkLayerHeaderLength + ip_header_len, sizeof(CTcpHeader));
	tcp_header_len = ((ntohs(tcp_header.nHLenAndFlag_) & 0xF000) >> 12) * 4;
	data = (*it_send)->GetData() + kLinkLayerHeaderLength + ip_header_len + tcp_header_len;

	buffer.append(data, (*it_send)->GetHeader()->iActualLength_ -
		(kLinkLayerHeaderLength + ip_header_len + tcp_header_len));
	file_name = buffer.substr(0, buffer.find("\r\n"));
	file_name = file_name.substr(file_name.find("GET") + 4, file_name.find("HTTP/") - (file_name.find("GET") + 4) - 1);

	int pos = buffer.find("Host") == std::string::npos?buffer.find("HOST"):buffer.find("Host") + 6;
	director = buffer.substr(pos, buffer.find("\r\n", pos) - pos);

	if (file_name == "/") {
		file_name = director + ".html";
	} else {
		int pos = file_name.rfind("/");
		if (pos != std::string::npos)
			file_name = file_name.substr(pos + 1);
		pos = file_name.find("?");
		if (pos != std::string::npos)
			file_name = file_name.substr(0, pos);
		pos = file_name.find("#");
		if (pos != std::string::npos)
			file_name = file_name.substr(0, pos);
	}
	full_file_name = file_path + director + "\\" + file_name;

	buffer.clear();
	for (auto it_recv = recv_obj.begin(); it_recv != recv_obj.end(); ++it_recv) {
		memcpy(&ip_header, (*it_recv)->GetData() + kLinkLayerHeaderLength, sizeof(CIpHeader));
		ip_header_len = (ip_header.ver_ihl_ & 0x0F) * 4;
		memcpy(&tcp_header, (*it_recv)->GetData() + kLinkLayerHeaderLength + ip_header_len, sizeof(CTcpHeader));
		tcp_header_len = ((ntohs(tcp_header.nHLenAndFlag_) & 0xF000) >> 12) * 4;
		data = (*it_recv)->GetData() + kLinkLayerHeaderLength + ip_header_len + tcp_header_len;

		buffer.append(data, ntohs(ip_header.tlen_) - (ip_header_len + tcp_header_len));
	}
	// 判断请求是否出错
	// buffer.erase(0, buffer.find("HTTP"));
	std::string state_str = buffer.substr(0, buffer.find("\r\n"));
	if (state_str.find("200") == std::string::npos) {
		return NO_RECEIVE_ERROR;
	}

	// encoding
	//int pos1 = buffer.find("Accept-Encoding");
	//if (pos1 != std::string::npos) {
	//	pos1 += strlen("Accept-Encoding") + 2;
	//	encoding = buffer.substr(pos1, buffer.find("\r\n", pos1) - pos1);
	//}
	int pos2 = buffer.find("Content-Encoding");
	if (pos2 != std::string::npos) {
		pos2 += strlen("Content-Encoding") + 2;
		encoding = buffer.substr(pos2, buffer.find("\r\n", pos2) - pos2);
	}

	// 创建文件信息
	CFileAttribute* file = new CFileAttribute;
	file->full_file_name_ = full_file_name;
	file->encoding_ = encoding;
	buffer.erase(0, buffer.find("\r\n\r\n") + 4);
	file->data_.swap(buffer);
	files_->push_back(file);
	
	return SUCCESS;
}
