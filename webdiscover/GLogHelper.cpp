#include "stdafx.h"
#include <fstream>
#include <string>
#include "GLogHelper.h"

//���������־��Ŀ¼��
#define LOGDIR "log"
// #define MKDIR "mkdir -p "LOGDIR

//����Ϣ������������ļ��� LOG(ERROR)
void SignalHandle(const char* data, int size)
{
    std::string str = std::string(data, size);

    std::ofstream fs("glog_dump.log", std::ios::app);
    fs<<str;
    fs.close();

    LOG(GERROR)<<str;
    // Ҳ����ֱ�������﷢���ʼ������֪ͨ��������������Ǳ��ص���εģ�ÿ�λص�ֻ���һ�д�����Ϣ��
	// ����������ļ�¼���ļ���Ҳ��Ҫ>��׷��ģʽ���ɣ����������﷢�ʼ�����Ų��Ǻ��ʺϣ��������ǿ�
	// �Ե���һ�� SHELL �� PYTHON �ű������˽ű����� sleep 3�����ң�Ȼ�󽫴�����Ϣͨ���ʼ������
	// ���ͳ�ȥ�������Ͳ���Ҫ��ؽű���ʱ��Ƶ��ִ�У��˷�Ч���ˡ�
}

//GLOG���ã�
GLogHelper::GLogHelper(char* program)
{
    //system(MKDIR);
    google::InitGoogleLogging(program);

    google::SetStderrLogging(google::INFO);		//���ü������ google::INFO ����־ͬʱ�������Ļ
    FLAGS_colorlogtostderr=true;	//�����������Ļ����־��ʾ��Ӧ��ɫ
    //google::SetLogDestination(google::GERROR,"log/error_");    //���� google::ERROR �������־�洢·�����ļ���ǰ׺
    google::SetLogDestination(google::INFO,LOGDIR"/INFO_");		 //���� google::INFO �������־�洢·�����ļ���ǰ׺
    google::SetLogDestination(google::WARNING,LOGDIR"/WARNING_");   //���� google::WARNING �������־�洢·�����ļ���ǰ׺
    google::SetLogDestination(google::GERROR,LOGDIR"/ERROR_");		//���� google::ERROR �������־�洢·�����ļ���ǰ׺
    FLAGS_logbufsecs = 0;        //������־�����Ĭ��Ϊ30�룬�˴���Ϊ�������
    FLAGS_max_log_size = 100;	 //�����־��СΪ 100MB
    FLAGS_stop_logging_if_full_disk = true;     //�����̱�д��ʱ��ֹͣ��־���
    google::SetLogFilenameExtension("91_");     //�����ļ�����չ����ƽ̨����������Ҫ���ֵ���Ϣ
    //google::InstallFailureSignalHandler();      //��׽ core dumped
    //google::InstallFailureWriter(&SignalHandle);    //Ĭ�ϲ�׽ SIGSEGV �ź���Ϣ���������� stderr������ͨ������ķ����Զ������>��ʽ��
}
//GLOG�ڴ�����
GLogHelper::~GLogHelper()
{
    google::ShutdownGoogleLogging();
}