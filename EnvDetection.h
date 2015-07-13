//	Author:ZOO

//			����
//		ö�ٽ���
//		ö�ٴ�������
//		ö�ٴ�������
//		�� Event
//		�� File
//		�� FileMapping
//
//				���÷���1
//		�����ڲ�����˵��ù��̣����Ե���˳�����Ϊ���£�������ÿ϶�ʧ��
//			EnvDetection::Construction(callproc);
//			EnvDetection::Start(0, 0);
//			EnvDetection::Stop();
//			EnvDetection::Destruction();
//		���������ú�ϵͳĬ��Ϊ����������ͣ�ÿ1����һ��
//		�����⵽�ˣ���ͨ�� callproc ֪ͨ������
//
//
//				���÷���2
//			EnvDetection::SimpleCall::Start(fun);
//		fun����Ϊ�ⲿ�ṩ�Ļص�֪ͨ������
//		��������֮��һ��ɨ���߳�ɨ�赽������Ϣ�����̻����fun������
//		fun�����ڲ�����ִ��������������ݷ���ֵ���ж��Ƿ������
//		����������ˣ��򷵻�true�Ϳ����ˣ����򷵻�false��
//		����֪ͨ���Ա�֤Ϊ���У����ǲ���֤ɨ��ģ���˳�ʱ����ǰ�������ᱻ����
//

#include <Windows.h>
#pragma once

namespace EnvDetection
{
	//	֪ͨ����������
	enum
	{
		ENV_DETECTION_TYPE_UNKNOW			= (1<<0),
		ENV_DETECTION_TYPE_PROCESS			= (1<<1),	//	֪ͨ1������һ������
		ENV_DETECTION_TYPE_WINDOW			= (1<<2),	//	֪ͨ2������һ�����ڱ���
		ENV_DETECTION_TYPE_WINDOW_CLASS		= (1<<3),	//	֪ͨ3������һ����������
		ENV_DETECTION_TYPE_EVENT			= (1<<4),	//	֪ͨ4������һ���ں��¼�
		ENV_DETECTION_TYPE_FILE				= (1<<5),	//	֪ͨ5������һ���ļ�
		ENV_DETECTION_TYPE_FILEMAPPING		= (1<<6),	//	֪ͨ6������һ���ڴ��ļ�ӳ��
	};

	//	��ǰִ��״̬
	enum
	{
		ENV_DETECTION_STATUS_CONSTRUCTION	= 1,		//	�Ѿ�������
		ENV_DETECTION_STATUS_DESTRUCTION	= 2,		//	�Ѿ�������
		ENV_DETECTION_STATUS_RUNNING		= 3,		//	��������
	};

	typedef struct _ENV_DETECTION_STRUCT_
	{
		int type;					//	����
		union
		{
			struct ENV_DETECTION_TYPE_PROCESS_STRUCT
			{
				WCHAR name[MAX_PATH];	//	��������
				DWORD PID;				//	����ID
			}process;
			struct ENV_DETECTION_TYPE_WINDOW_STRUCT
			{
				WCHAR name[MAX_PATH];	//	�����ı�����
				HANDLE hWnd;			//	���ھ��
			}window;
			struct ENV_DETECTION_TYPE_WINDOW_CLASS_STRUCT
			{
				WCHAR name[MAX_PATH];	//	����������
				HANDLE hWnd;			//	���ھ��
			}window_class;
			struct ENV_DETECTION_TYPE_EVENT_STRUCT
			{
				WCHAR name[MAX_PATH];	//	Event����
			}event;
			struct ENV_DETECTION_TYPE_FILE_STRUCT
			{
				WCHAR name[MAX_PATH];	//	�ļ�����
			}file;
			struct ENV_DETECTION_TYPE_FILEMAPPING_STRUCT
			{
				WCHAR name[MAX_PATH];	//	�ļ�ӳ������
			}filemapping;
		};
	}ENV_DETECTION_STRUCT;

	//////////////////////////////////////////////////////////////////////////
	//			ɨ��֪ͨ�ص������ⲿ�ṩ��Ҳ���Բ��ṩ
	//		���ɨ�赽ĳ������Ŀ�꣬��ͨ���˺�������֪ͨ
	//		�˺����ڣ�������Ӧ���࣬Ӧ�������ٷ���
	typedef void (*ENV_DETECTION_NOTIFY)(ENV_DETECTION_STRUCT *buf);

	//////////////////////////////////////////////////////////////////////////
	//			Ϊ�˱���ÿ��������Ҫ��ʼ��һ�λ���������������һ�λ������Ĺ���
	//		proc	Ϊ�ⲿ�����֪ͨ�ص�
	//		�������Բ�����Ϊ NULL
	bool Construction(ENV_DETECTION_NOTIFY proc);

	//////////////////////////////////////////////////////////////////////////
	//				������������
	//		�������������Զ�ֹͣ�������Ҫ�ֶ�ֹͣ
	//		���ԣ���Ҫ����stop��Ȼ��ſ��Ե�������
	bool Destruction();

	//////////////////////////////////////////////////////////////////////////
	//				�����������
	//		scan	����Ϊ��Ҫ�������ͣ����Ϊ0������0xFFFFFFFF����ȫ�����Ͷ�Ҫ���
	//		timer	ÿ���μ���ʱ��������λΪ���룬���Ϊ0����Ĭ�ϼ��1s
	bool Start(DWORD scan, int timer);

	//////////////////////////////////////////////////////////////////////////
	//				ֹͣ�������
	//		�����������ȴ�5��֮��ŷ���
	//		����ʱ�ᱣ֤Ŀ���̻߳����
	//		���������Ȼ��������ǿ�н���
	//		��һ�㲻��������������������������������û��ص�û���˳���
	bool Stop();

	//////////////////////////////////////////////////////////////////////////
	//				��ȡ��ǰģ��ִ��״̬
	//		����ֵ����������
	//			����Ѿ����죬��û�����У������н������򷵻�	ENV_DETECTION_STATUS_CONSTRUCTION
	//			����Ѿ���ʼ���У��򷵻�						ENV_DETECTION_STATUS_RUNNING
	//			���û�й��죬������֮���򷵻�				ENV_DETECTION_STATUS_DESTRUCTION
	int GetStatus();

	//	��ʹ�÷���
	namespace SimpleCall
	{
		//////////////////////////////////////////////////////////////////////////
		//			�û��ṩ�Ļص�����
		//		���ݷ���ֵ���жϼ���߳��Ƿ����
		//		������� false ������߳̾ͼ���
		//		������� true �� ����߳̾��˳���
		//		����Ϊ ENV_DETECTION_STRUCT �ṹָ��
		typedef bool (*ENV_DETECTION_SIMPLE_CALL_NOTIFY)(ENV_DETECTION_STRUCT *buf);
		//////////////////////////////////////////////////////////////////////////
		//				�򵥵�ʹ��
		bool Start(ENV_DETECTION_SIMPLE_CALL_NOTIFY fun);
	}
}