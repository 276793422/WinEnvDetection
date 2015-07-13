//	Author:ZOO

//			功能
//		枚举进程
//		枚举窗口名字
//		枚举窗口类名
//		打开 Event
//		打开 File
//		打开 FileMapping
//
//				调用方法1
//		由于内部检测了调用过程，所以调用顺序必须为如下，否则调用肯定失败
//			EnvDetection::Construction(callproc);
//			EnvDetection::Start(0, 0);
//			EnvDetection::Stop();
//			EnvDetection::Destruction();
//		当这样调用后，系统默认为监测所有类型，每1秒检测一次
//		如果检测到了，则通过 callproc 通知调用者
//
//
//				调用方法2
//			EnvDetection::SimpleCall::Start(fun);
//		fun函数为外部提供的回调通知函数，
//		这样调用之后，一旦扫描线程扫描到敏感信息，立刻会调用fun函数，
//		fun函数内部可以执行任意操作，根据返回值来判断是否继续，
//		如果不继续了，则返回true就可以了，否则返回false，
//		函数通知可以保证为串行，但是不保证扫描模块退出时，当前函数不会被触发
//

#include <Windows.h>
#pragma once

namespace EnvDetection
{
	//	通知及检索类型
	enum
	{
		ENV_DETECTION_TYPE_UNKNOW			= (1<<0),
		ENV_DETECTION_TYPE_PROCESS			= (1<<1),	//	通知1，发现一个进程
		ENV_DETECTION_TYPE_WINDOW			= (1<<2),	//	通知2，发现一个窗口标题
		ENV_DETECTION_TYPE_WINDOW_CLASS		= (1<<3),	//	通知3，发现一个窗口类名
		ENV_DETECTION_TYPE_EVENT			= (1<<4),	//	通知4，发现一个内核事件
		ENV_DETECTION_TYPE_FILE				= (1<<5),	//	通知5，发现一个文件
		ENV_DETECTION_TYPE_FILEMAPPING		= (1<<6),	//	通知6，发现一个内存文件映射
	};

	//	当前执行状态
	enum
	{
		ENV_DETECTION_STATUS_CONSTRUCTION	= 1,		//	已经构造了
		ENV_DETECTION_STATUS_DESTRUCTION	= 2,		//	已经析构了
		ENV_DETECTION_STATUS_RUNNING		= 3,		//	正在运行
	};

	typedef struct _ENV_DETECTION_STRUCT_
	{
		int type;					//	类型
		union
		{
			struct ENV_DETECTION_TYPE_PROCESS_STRUCT
			{
				WCHAR name[MAX_PATH];	//	进程名字
				DWORD PID;				//	进程ID
			}process;
			struct ENV_DETECTION_TYPE_WINDOW_STRUCT
			{
				WCHAR name[MAX_PATH];	//	窗口文本名字
				HANDLE hWnd;			//	窗口句柄
			}window;
			struct ENV_DETECTION_TYPE_WINDOW_CLASS_STRUCT
			{
				WCHAR name[MAX_PATH];	//	窗口类名字
				HANDLE hWnd;			//	窗口句柄
			}window_class;
			struct ENV_DETECTION_TYPE_EVENT_STRUCT
			{
				WCHAR name[MAX_PATH];	//	Event名字
			}event;
			struct ENV_DETECTION_TYPE_FILE_STRUCT
			{
				WCHAR name[MAX_PATH];	//	文件名字
			}file;
			struct ENV_DETECTION_TYPE_FILEMAPPING_STRUCT
			{
				WCHAR name[MAX_PATH];	//	文件映射名字
			}filemapping;
		};
	}ENV_DETECTION_STRUCT;

	//////////////////////////////////////////////////////////////////////////
	//			扫描通知回调，由外部提供，也可以不提供
	//		如果扫描到某个敏感目标，则通过此函数向外通知
	//		此函数内，操作不应过多，应尽量快速返回
	typedef void (*ENV_DETECTION_NOTIFY)(ENV_DETECTION_STRUCT *buf);

	//////////////////////////////////////////////////////////////////////////
	//			为了避免每次启动都要初始化一次环境，所以这里做一次环境检测的构造
	//		proc	为外部传入的通知回调
	//		参数绝对不可以为 NULL
	bool Construction(ENV_DETECTION_NOTIFY proc);

	//////////////////////////////////////////////////////////////////////////
	//				环境检测的析构
	//		环境析构不会自动停止，检测需要手动停止
	//		所以，先要调用stop，然后才可以调用这里
	bool Destruction();

	//////////////////////////////////////////////////////////////////////////
	//				启动环境检测
	//		scan	参数为需要检测的类型，如果为0，或者0xFFFFFFFF，则全部类型都要检测
	//		timer	每两次检测的时间间隔，单位为毫秒，如果为0，则默认间隔1s
	bool Start(DWORD scan, int timer);

	//////////////////////////////////////////////////////////////////////////
	//				停止环境检测
	//		这个函数最多会等待5秒之后才返回
	//		返回时会保证目标线程会结束
	//		如果不能自然结束，则强行结束
	//		（一般不会出现这种情况，出现这种情况可能是用户回调没有退出）
	bool Stop();

	//////////////////////////////////////////////////////////////////////////
	//				获取当前模块执行状态
	//		返回值可能有三种
	//			如果已经构造，但没有运行，或运行结束，则返回	ENV_DETECTION_STATUS_CONSTRUCTION
	//			如果已经开始运行，则返回						ENV_DETECTION_STATUS_RUNNING
	//			如果没有构造，或析构之后，则返回				ENV_DETECTION_STATUS_DESTRUCTION
	int GetStatus();

	//	简单使用方法
	namespace SimpleCall
	{
		//////////////////////////////////////////////////////////////////////////
		//			用户提供的回调函输
		//		根据返回值，判断检测线程是否继续
		//		如果返回 false ，检测线程就继续
		//		如果返回 true ， 检测线程就退出了
		//		参数为 ENV_DETECTION_STRUCT 结构指针
		typedef bool (*ENV_DETECTION_SIMPLE_CALL_NOTIFY)(ENV_DETECTION_STRUCT *buf);
		//////////////////////////////////////////////////////////////////////////
		//				简单的使用
		bool Start(ENV_DETECTION_SIMPLE_CALL_NOTIFY fun);
	}
}