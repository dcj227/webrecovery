#pragma once

#include <glog/logging.h>
#include <glog/raw_logging.h>

//����Ϣ������������ļ��� LOG(ERROR)
void SignalHandle(const char* data, int size);

class GLogHelper
{
public:
    //GLOG���ã�
    GLogHelper(char* program);
    //GLOG�ڴ�����
    ~GLogHelper();
};