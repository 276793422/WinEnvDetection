#include "stdafx.h"
#include "EnvDetection.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <process.h>


#define _ENV_DETECTION_WAIT_THREAD_EXIT_TIMEOUT			1000*5
#define _ENV_DETECTION_THREAD_DETECTION_DEFAULT_DELAY	1000

static HANDLE g_EventExit = NULL;												//	�߳��˳��ź�
static HANDLE g_ThreadHandle = NULL;											//	�߳̾��
static int g_nStatus = EnvDetection::ENV_DETECTION_STATUS_DESTRUCTION;			//	��ǰ��״̬
static EnvDetection::ENV_DETECTION_NOTIFY g_NotifyProc = NULL;					//	֪ͨ����
static EnvDetection::ENV_DETECTION_STRUCT g_NotifyStruct;						//	֪ͨ�����Ľṹ��
static DWORD g_dwScanType = 0xFFFFFFFF;											//	ɨ������


//////////////////////////////////////////////////////////////////////////
//	ʵ��


//////////////////////////////////////////////////////////////////////////
//	����ɨ��
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
			|| (_wcsicmp(pe32.szExeFile, L"procmon.exe") == 0))		//	procmon����
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
				//	���֪ͨ���������ڣ�����һЩĬ�ϲ���
			}
		}
		bMore = ::Process32Next(hProcessSnap, &pe32);
	}
	::CloseHandle(hProcessSnap);
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	����ö��
static BOOL CALLBACK __EnumWindowNameProc_(HWND hwnd, LPARAM lParam)
{
#if 0
	WCHAR *wBuf = (WCHAR *)lParam;
	//	��ȡ�����ı�
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
				//	���֪ͨ���������ڣ�����һЩĬ�ϲ���
			}
		}
	}
#endif
	return 1;
}

//	���ڱ���ɨ��
static int __WindowNameDetection(void *buf)
{
	EnumChildWindows(GetDesktopWindow(), __EnumWindowNameProc_, (LONG_PTR)buf);
	//	���÷��������������FindWindow
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	����ö��
static BOOL CALLBACK __EnumWindowClassProc_(HWND hwnd, LPARAM lParam)
{
	WCHAR *wBuf = (WCHAR *)lParam;
	int len;
	//	��ȡ��������
	len = GetClassNameW(hwnd, wBuf, MAX_PATH);
	if (len)
	{
		wBuf[len] = L'\0';
		if ((_wcsicmp(wBuf, L"PROCMON_WINDOW_CLASS") == 0))		//	PROCMON ����������
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
				//	���֪ͨ���������ڣ�����һЩĬ�ϲ���
			}
		}
	}
	return 1;
}

//	��������ɨ��
static int __WindowClassDetection(void *buf)
{
	EnumChildWindows(GetDesktopWindow(), __EnumWindowClassProc_, (LONG_PTR)buf);
	//	���÷��������������FindWindow
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	Event���
static int __EventDetection(void *buf)
{
#if 0
	HANDLE h;
	return 0;
	h = OpenEventW(EVENT_ALL_ACCESS, 0, L"SBX_SHOW_PROC_LIST");		//	360��һ�� Event
	if (h || (GetLastError() != 2))
	{
		CloseHandle(h);
		g_NotifyStruct.type = EnvDetection::ENV_DETECTION_TYPE_EVENT;
		wcscpy_s(g_NotifyStruct.event.name, sizeof(g_NotifyStruct.event.name) >> 1, L"SBX_SHOW_PROC_LIST");
		g_NotifyProc(&g_NotifyStruct);
	}
	h = OpenEventW(EVENT_ALL_ACCESS, 0, L"Global\\TAPICLUC_All");	//	360��һ�� Event
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
//	�ļ����
static int __FileDetection(void *buf)
{
	//	CreateFile
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	�ڴ��ļ�ӳ��
static int __FileMappingDetection(void *buf)
{
	//	CreateFileMapping
	return 0;
}

//	��ѭ��
static void __EnvDetectionThreadProc(void * pParam)
{
	int timer = (int)pParam;
	WCHAR buffer[MAX_PATH];
	while (1)
	{
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_PROCESS)
		{
			__ProcessDetection(buffer);		//	����ɨ��
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_WINDOW)
		{
			__WindowNameDetection(buffer);	//	������ɨ��
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_WINDOW_CLASS)
		{
			__WindowClassDetection(buffer);	//	��������ɨ��
		}
#if 0
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_EVENT)
		{
			__EventDetection(buffer);		//	Eventɨ��
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_FILE)
		{
			__FileDetection(buffer);		//	�ļ�ɨ��
		}
		if (g_dwScanType & EnvDetection::ENV_DETECTION_TYPE_FILEMAPPING)
		{
			__FileMappingDetection(buffer);	//	�ڴ��ļ�ӳ��
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

//	Ϊ�˱���ÿ��������Ҫ��ʼ��һ�λ���������������һ�λ������Ĺ���
static bool __Construction(EnvDetection::ENV_DETECTION_NOTIFY proc)
{
	g_EventExit = CreateEvent(NULL, TRUE, FALSE, NULL);
	ResetEvent(g_EventExit);
	g_ThreadHandle = NULL;
	g_NotifyProc = proc;
	g_dwScanType = 0xFFFFFFFF;	//	Ĭ������Ϊȫ��ɨ��
	return true;
}

//	������������
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

//	�����������
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

//	ֹͣ�������
static bool __Stop()
{
	DWORD waitReturn;
	SetEvent(g_EventExit);
	waitReturn = WaitForSingleObject(g_ThreadHandle, _ENV_DETECTION_WAIT_THREAD_EXIT_TIMEOUT);
	if (waitReturn == WAIT_OBJECT_0)
	{
		//	�����˳�
	}
	else if (waitReturn == WAIT_TIMEOUT)
	{
		//	��û�˳�,��ʱ�ˣ���������Ƚ��ټ���
		//	һ�������ˣ����п��ܾ����û�ע���֪ͨ��������̫��ʱ��û�з���
		//	��������ǳ��Ӧ�þ������⣬
		//	���������ʱ��Ҫ������ô���ˣ�����ǿɱ�����߷���ʧ��
		TerminateThread(g_ThreadHandle, -1);
		ResetEvent(g_EventExit);
	}
	g_ThreadHandle = NULL;

	return true;
}

//////////////////////////////////////////////////////////////////////////
//	�ӿ�

//	Ϊ�˱���ÿ��������Ҫ��ʼ��һ�λ���������������һ�λ������Ĺ���
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

//	������������
bool EnvDetection::Destruction()
{
	//	����������У���ֱ�ӷ���ʧ�ܣ���Ҫ��ֹͣ���У�������
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

//	�����������
bool EnvDetection::Start(DWORD scan, int timer)
{
	if (g_nStatus != ENV_DETECTION_STATUS_CONSTRUCTION)
	{
		return false;
	}
	g_nStatus = ENV_DETECTION_STATUS_RUNNING;

	return __Start(scan, timer);
}

//	ֹͣ�������
bool EnvDetection::Stop()
{
	if (g_nStatus != ENV_DETECTION_STATUS_RUNNING)
	{
		return false;
	}
	g_nStatus = ENV_DETECTION_STATUS_CONSTRUCTION;

	return __Stop();
}

//	��ȡ��ǰģ��ִ��״̬
int EnvDetection::GetStatus()
{
	return g_nStatus;
}

#undef _ENV_DETECTION_WAIT_THREAD_EXIT_TIMEOUT
#undef _ENV_DETECTION_THREAD_DETECTION_DEFAULT_DELAY



//////////////////////////////////////////////////////////////////////////
//			�򵥵���
static EnvDetection::SimpleCall::ENV_DETECTION_SIMPLE_CALL_NOTIFY g_NotifyProcSimple = NULL;
static LONG g_NotifyProcSimpleOnceAtomic = 0;

//	�̺߳���
//		��ʵ�������߳���ʵ�֣�����Ͳ�����Ƶ���ش����߳̾��ǲ������������
//		����������һ��ԭ���ü򵥵���������صģ������ô����Ǽ�⵽��Ŀ������ֱ����Ӧ
//			���ԣ�һ����˵������Ӵ���ǰ�����������ʱ�򣬼���߳̾��Ѿ������ˣ�
//			���֪ͨ�߳�Ҳ����ʮ��Ƶ���ر�����
//			������������һֱ��⻷�����Ҽ�⵽��Ŀ�����Ҳ���˳��Ļ���ʹ�ó��淽�������ã��Ҹ���ȷ
static void __EnvDetectionSimpleCallThreadProc(void *buf)
{
	//	��ǰ״̬���Ϊ�������У���ȥ�����ص������򲻹�
	if (EnvDetection::GetStatus() == EnvDetection::ENV_DETECTION_STATUS_RUNNING)
	{
		if (g_NotifyProcSimple((EnvDetection::ENV_DETECTION_STRUCT*)buf))
		{
			//	�����ˣ��߳��˳�
			EnvDetection::Stop();
			EnvDetection::Destruction();
		}
	}
	//	����������ԭ�Ӳ�����0
	InterlockedBitTestAndReset(&g_NotifyProcSimpleOnceAtomic, 1);
	_endthread();
}

//	�򵥵��õ��ڲ�֪ͨ�ص�
static void __EnvDetectionSimpleCallNotify(EnvDetection::ENV_DETECTION_STRUCT *buf)
{
	//	ԭ�Ӳ�������Ψһ������1
	if (InterlockedBitTestAndSet(&g_NotifyProcSimpleOnceAtomic, 1) == 0)
	{
		//	�����ж�ֻΪ��ȫ������������У��ͷַ����û���
		//	��������˵����������������еĻ�������Ҳ�����ߵ���
		//	����Ϊ�˷�ֹ��һ���Ͼ������߳̿����ܴ��
		//	���Ҵ��������£�����ǰ���ԭ�Ӳ����Ͱ����̽�ס�ˣ����ᵽ����
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

//	��ʹ������
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
