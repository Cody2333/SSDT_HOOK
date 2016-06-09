#ifndef _SSDT_H_
#define _SSDT_H_

#include <ntddk.h>

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID   ServiceTableBase;			// SSDT (System Service Dispatch Table)的基地址
	PULONG  ServiceCounterTableBase;	// 用于checked builds, 包含SSDT中每个服务被调用的次数
	ULONG   NumberOfService;			// 服务函数的个数, NumberOfService*4 就是整个地址表的大小
	ULONG   ParamTableBase;				// SSPT (System Service Parameter Table)的基地址
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

//
__declspec(dllimport)  SYSTEM_SERVICE_TABLE KeServiceDescriptorTable;


// 根据 Zw_function 获取服务ID
#define SERVICE_ID(_function)			(*(PULONG)((PUCHAR)_function + 1))

// 根据 Zw_function 获取 Nt_function的地址
#define SERVICE_FUNCTION(_function)		\
		((ULONG)KeServiceDescriptorTable.ServiceTableBase + 4*SERVICE_ID(_function))


// ------------------------------------------------------

NTSTATUS Hook(ULONG OldService, ULONG NewService);
NTSTATUS UnHook(ULONG OldService);
VOID InitServicesTable();
VOID WPON();
VOID WPOFF();

// ------------------------------------------------------
ULONG OldServiceAddressTable[1024];			// 保存旧的服务函数地址

LARGE_INTEGER m_UserTime;
LARGE_INTEGER m_KernelTime;

#endif
