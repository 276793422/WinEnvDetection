#include "stdafx.h"
#include "EnvDetection.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <process.h>


#define _ENV_DETECTION_WAIT_THREAD_EXIT_TIMEOUT			1000*5
#define _ENV_DETECTION_THREAD_DETECTION_DEFAULT_DELAY	1000

static HANDLE g_EventExit = NULL;												//	线程退出信号
static HANDLE g_ThreadHandle = NULL;											//	线程句柄
static int g_nStatus = EnvDetection::ENV_DETECTION_STATUS_DESTRUCTION;			//	当前类状态
static EnvDetection::ENV_DETECTION_NOTIFY g_NotifyProc = NULL;					//	通知函数
static EnvDetection::ENV_DETECTION_STRUCT g_NotifyStruct;						//	通知函数的结构体
static DWORD g_dwScanType = 0xFFFFFFFF;											//	扫描类型


//////////////////////////////////////////////////////////////////////////
//	实现


//////////////////////////////////////////////////////////////////////////
//	进程扫描
static int __ProcessDetection(void *buf)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	int count = 0;
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return -1;
	}
	BOOL bMore = ::Process32First(hProcessSnap, &pe32);
	while (bMore)
	{
		count++;
		if ((_wcsicmp(pe32.szExeFile, L"PCHunter32.exe") == 0)		//	PCHunter
			|| (_wcsicmp(pe32.szExeFile, L"PCHunter64.exe") == 0)
			|| (_wcsicmp(pe32.szExeFile, L"procmon.exe") == 0))		//	procmon进程
		{
			if (g_NotifyProc)
			{
				g_NotifyStruct.type = EnvDetection::ENV_DETECTION_TYPE_PROCESS;
				wcscpy_s(g_NotifyStruct.process.name, sizeof(g_NotifyStruct.process.name) >> 1, pe32.szExeFile);
				g_NotifyStruct.process.PID = pe32.th32ProcessID;
				g_NotifyProc(&g_NotifyStruct);
			}
			else
			{
				//	如果通知函数不存在，则做一些默认操作
			}
		}
		bMore = ::Process32Next(hProcessSnap, &pe32);
	}
	::CloseHandle(hProcessSnap);
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	窗口枚举
static BOOL CALLBACK __EnumWindowNameProc_(HWND hwnd, LPARAM lParam)
{
#if 0
	WCHAR *wBuf = (WCHAR *)lParam;
	//	获取窗口文本
	int len = GetWindowTextW(hwnd, wBuf, MAX_PATH);
	if (len)
	{
		wBuf[len] = L'\0';
		if ((_wcsicmp(wBuf, L"spyxx") == 0))
		{
			if (g_NotifyProc)
			{
				g_NotifyStruct.type = EnvDetection::ENV_DETECTION_TYPE_WINDOW;
				wcscpy_s(g_NotifyStruct.window.name, sizeof(g_NotifyStruct.window.name) >> 1, wBuf);
				g_NotifyStruct.window.hWnd = hwnd;
				g_NotifyProc(&g_NotifyStruct);
			}
			else
			{
				//	如果通知函数不存在，则做一些默认操作
			}
		}
	}
#endif
	return 1;
}

//	窗口标题扫描
static int __WindowNameDetection(void *buf)
{
	EnumChildWindows(GetDesktopWindow(), __EnumWindowNameProc_, (LONG_PTR)buf);
	//	备用方案，这里可以用FindWindow
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	窗口枚举
static BOOL CALLBACK __EnumWindowClassProc_(HWND hwnd, LPARAM lParam)
{
	WCHAR *wBuf = (WCHAR *)lParam;
	int len;
	//	获取窗口类名
	len = GetClassNameW(hwnd, wBuf, MAX_PATH);
	if (len)
	{
		wBuf[len] = L'\0';
		if ((_wcsicmp(wBuf, L"PROCMON_WINDOW_CLASS") == 0))		//	PROCMON 主窗口类名
		{
			if (g_NotifyProc)
			{
				g_NotifyStruct.type = EnvDetection::ENV_DETECTION_TYPE_WINDOW_CLASS;
				wcscpy_s(g_NotifyStruct.window_class.name, sizeof(g_NotifyStruct.window_class.name) >> 1, wBuf);
				g_NotifyStruct.window_class.hWnd = hwnd;
				g_NotifyProc(&g_NotifyStruct);
			}
			else
			{
				//	如果通知函数不存在，则做一些默认操作
			}
		}
	}
	return 1;
}

//	窗口类名扫描
static int __WindowClassDetection(void *buf)
{
	EnumChildWindows(GetDesktopWindow(), __EnumWindowClassProc_, (LONG_PTR)buf);
	//	备用方案，这里可以用FindWindow
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	Event检测
static int __EventDetection(void *buf)
{
#if 0
	HANDLE h;
	return 0;
	h = OpenEventW(EVENT_ALL_ACCESS, 0, L"SBX_SHOW_PROC_LIST");		//	360的一个 Event
	if (h || (GetLastError() != 2))
	{
		CloseHandle(h);
		g_NotifyStruct.type = EnvDetection::ENV_DETECTION_TYPE_EVENT;
		wcscpy_s(g_NotifyStruct.event.name, sizeof(g_NotifyStruct.event.name) >> 1, L"SBX_SHOW_PROC_LIST");
		g_NotifyProc(&g_NotifyStruct);
	}
	h = OpenEventW(EVENT_ALL_ACCESS, 0, L"Global\\TAPICLUC_All");	//	360的一个 Event
	if (h || (GetLastError() != 2))
	{
		CloseHandle(h);
		g_NotifyStruct.type = EnvDetection::ENV_DETECTION_TYPE_EVENT;
		wcscpy_s(g_NotifyStruct.event.name, sizeof(g_NotifyStruct.event.name) >> 1, L"Global\\TAPICLUC_All");
		g_NotifyProc(&g_NotifyStruct);
	}
#endif
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	文件检测
static int __FileDetection(void *buf)
{
	//	CreateFile
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	内存文件映射
static int __FileMappingDetection(void *buf)
{
	//	CreateFileMapping
	return 0;
}

//	主循环
static void __EnvDetectionThreadProc(void * pParam)
{
	int timer = (int)pParam;
	WCHAR buffer[MAX_PATH];
	while (1)
	{
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_PROCESS)
		{
			__ProcessDetection(buffer);		//	进程扫描
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_WINDOW)
		{
			__WindowNameDetection(buffer);	//	窗口名扫描
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_WINDOW_CLASS)
		{
			__WindowClassDetection(buffer);	//	窗口类名扫描
		}
#if 0
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_EVENT)
		{
			__EventDetection(buffer);		//	Event扫描
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_FILE)
		{
			__FileDetection(buffer);		//	文件扫描
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_FILEMAPPING)
		{
			__FileMappingDetection(buffer);	//	内存文件映射
		}
#endif
		if (WaitForSingleObject(g_EventExit, timer) == WAIT_OBJECT_0)
		{
			break;
		}
	}
	ResetEvent(g_EventExit);
	_endthread();
}

//	为了避免每次启动都要初始化一次环境，所以这里做一次环境检测的构造
static bool __Construction(EnvDetection::ENV_DETECTION_NOTIFY proc)
{
	g_EventExit = CreateEvent(NULL, TRUE, FALSE, NULL);
	ResetEvent(g_EventExit);
	g_ThreadHandle = NULL;
	g_NotifyProc = proc;
	g_dwScanType = 0xFFFFFFFF;	//	默认设置为全部扫描
	return true;
}

//	环境检测的析构
static bool __Destruction()
{
	if (g_EventExit)
	{
		CloseHandle(g_EventExit);
		g_EventExit = NULL;
	}
	if (g_ThreadHandle)
	{
		CloseHandle(g_ThreadHandle);
		g_ThreadHandle = NULL;
	}
	g_dwScanType = 0xFFFFFFFF;
	return true;
}

//	启动环境检测
static bool __Start(DWORD scan, int timer)
{
	if (0 == scan)
	{
		g_dwScanType = 0xFFFFFFFF;
	}
	else
	{
		g_dwScanType = scan;
	}
	if (timer == 0)
	{
		timer = _ENV_DETECTION_THREAD_DETECTION_DEFAULT_DELAY;
	}

	g_ThreadHandle = (HANDLE)_beginthread(__EnvDetectionThreadProc, 0, (void*)timer);

	return true;
}

//	停止环境检测
static bool __Stop()
{
	DWORD waitReturn;
	SetEvent(g_EventExit);
	waitReturn = WaitForSingleObject(g_ThreadHandle, _ENV_DETECTION_WAIT_THREAD_EXIT_TIMEOUT);
	if (waitReturn == WAIT_OBJECT_0)
	{
		//	正常退出
	}
	else if (waitReturn == WAIT_TIMEOUT)
	{
		//	还没退出,超时了，这种情况比较少见，
		//	一旦发生了，很有可能就是用户注册的通知函数那里太长时间没有返回
		//	这种情况非常差，应该尽量避免，
		//	在所难免的时候，要考虑怎么办了，或者强杀，或者返回失败
		TerminateThread(g_ThreadHandle, -1);
		ResetEvent(g_EventExit);
	}
	g_ThreadHandle = NULL;

	return true;
}

//////////////////////////////////////////////////////////////////////////
//	接口

//	为了避免每次启动都要初始化一次环境，所以这里做一次环境检测的构造
bool EnvDetection::Construction(ENV_DETECTION_NOTIFY proc)
{
	if (proc == NULL || proc == 0)
	{
		return false;
	}
	if (g_nStatus != ENV_DETECTION_STATUS_DESTRUCTION)
	{
		return false;
	}
	g_nStatus = ENV_DETECTION_STATUS_CONSTRUCTION;
	return __Construction(proc);
}

//	环境检测的析构
bool EnvDetection::Destruction()
{
	//	如果正在运行，就直接返回失败，需要先停止运行，再析构
	if (g_nStatus == ENV_DETECTION_STATUS_RUNNING)
	{
		return false;
	}
	if (g_nStatus == ENV_DETECTION_STATUS_DESTRUCTION)
	{
		return false;
	}
	g_nStatus = ENV_DETECTION_STATUS_DESTRUCTION;

	return __Destruction();
}

//	启动环境检测
bool EnvDetection::Start(DWORD scan, int timer)
{
	if (g_nStatus != ENV_DETECTION_STATUS_CONSTRUCTION)
	{
		return false;
	}
	g_nStatus = ENV_DETECTION_STATUS_RUNNING;

	return __Start(scan, timer);
}

//	停止环境检测
bool EnvDetection::Stop()
{
	if (g_nStatus != ENV_DETECTION_STATUS_RUNNING)
	{
		return false;
	}
	g_nStatus = ENV_DETECTION_STATUS_CONSTRUCTION;

	return __Stop();
}

//	获取当前模块执行状态
int EnvDetection::GetStatus()
{
	return g_nStatus;
}

#undef _ENV_DETECTION_WAIT_THREAD_EXIT_TIMEOUT
#undef _ENV_DETECTION_THREAD_DETECTION_DEFAULT_DELAY



//////////////////////////////////////////////////////////////////////////
//			简单调用
static EnvDetection::SimpleCall::ENV_DETECTION_SIMPLE_CALL_NOTIFY g_NotifyProcSimple = NULL;
static LONG g_NotifyProcSimpleOnceAtomic = 0;

//	线程函数
//		其实这里用线程来实现，本身就不合理，频繁地创建线程就是不合理的做法，
//		但是这里有一个原因，用简单调用来做监控的，最大的用处就是检测到有目标程序就直接响应
//			所以，一般来说，这里接触到前几个检测结果的时候，检测线程就已经结束了，
//			这个通知线程也不会十分频繁地被创建
//			如果真的有需求一直检测环境，且检测到了目标程序也不退出的话，使用常规方法检测更好，且更精确
static void __EnvDetectionSimpleCallThreadProc(void *buf)
{
	//	当前状态如果为正在运行，才去触发回调，否则不管
	if (EnvDetection::GetStatus() == EnvDetection::ENV_DETECTION_STATUS_RUNNING)
	{
		if (g_NotifyProcSimple((EnvDetection::ENV_DETECTION_STRUCT*)buf))
		{
			//	不玩了，线程退出
			EnvDetection::Stop();
			EnvDetection::Destruction();
		}
	}
	//	工作结束，原子操作置0
	InterlockedBitTestAndReset(&g_NotifyProcSimpleOnceAtomic, 1);
	_endthread();
}

//	简单调用的内部通知回调
static void __EnvDetectionSimpleCallNotify(EnvDetection::ENV_DETECTION_STRUCT *buf)
{
	//	原子操作测试唯一，且置1
	if (InterlockedBitTestAndSet(&g_NotifyProcSimpleOnceAtomic, 1) == 0)
	{
		//	这里判断只为安全，如果正在运行，就分发给用户，
		//	理论上来说，如果不是正在运行的话，这里也不会走到，
		//	但是为了防止万一，毕竟创建线程开销很大的
		//	而且大多数情况下，都是前面的原子操作就把流程截住了，不会到这里
		if (EnvDetection::GetStatus() == EnvDetection::ENV_DETECTION_STATUS_RUNNING)
		{
			_beginthread(__EnvDetectionSimpleCallThreadProc, 0, (void*)buf);
		}
		if (EnvDetection::GetStatus() != EnvDetection::ENV_DETECTION_STATUS_RUNNING)
		{
			g_NotifyProcSimpleOnceAtomic = 0;
		}
	}
}

//	简单使用启动
bool EnvDetection::SimpleCall::Start(ENV_DETECTION_SIMPLE_CALL_NOTIFY fun)
{
	if (fun == NULL || fun == 0)
	{
		return false;
	}
	if (false == EnvDetection::Construction(__EnvDetectionSimpleCallNotify))
	{
		return false;
	}
	if (false == EnvDetection::Start(0, 0))
	{
		EnvDetection::Destruction();
		return false;
	}
	g_NotifyProcSimple = fun;
	g_NotifyProcSimpleOnceAtomic = 0;
	return true;
}
