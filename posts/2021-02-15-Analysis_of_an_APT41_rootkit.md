## Analysis of an APT41 rootkit

Recently I wanted to analyse some malware kernel code, so I downloaded an APT41
sample from [https://vx-underground.org/](vx-underground).

Here are some basic infos about the sample: 
```
Size: 12928
SHA1: a34591abefb327e3aa317ca49b0246caae8d7c5d
type: PE32 executable (native) Intel 80386, for MS Windows
```

I will not talk about the infection chain or APT41. It's just a technical
analysis of the malware code. The sample popped on virus total during 2015 but 
is probably a bit older than that, as its compilation date is 2011 and 
because Securelist [talked about](https://securelist.com/winnti-faq-more-than-just-a-game/57585/) 
a similar sample during 2013.

We'll see in the analysis that the driver targets old Windows versions, from
2000 to Vista.

## Analysis

### Initialization

The driver has two objectives, hide connections on the system, and eventually block
some others. 
We´ll see that it achieves this by hooking very specific functions, and by 
initiating a cover channel with userland by adding functionalities to a syscall.

The driver starts by calling the routine `IoCreateDevice` with 
`FILE_DEVICE_UNKNOWN (0x22)` as DeviceType, `FILE_DEVICE_SECURE_OPEN (0x100)`
as DeviceCharacteristics and `\\Device\\PORTLESS_DeviceName` as DeviceName.

As the created object is not used at all by the driver, we can easily guess that
this is used as a mutex, just to be sure that the driver isn't loaded multiple 
time in memory.

![call to IoCreateDevice](../../../../static/APT41_driver_analysis/call_IoCreateDevice.png)

Its next step is to retrieve the address of the global data `IoDriverObjectType`
with `MmGetSystemRoutineAddress`. It will use this data to find and delete 
itself in the `struct _LIST_ENTRY TypeList`, but more on that later.

![loading IoDriverObjectType](../../../../static/APT41_driver_analysis/load_IoDriverObjectType.png)

I wrote above that the driver targets multiple versions of Windows. As it will
perform precise hooking in the kernel, it needs to know the version of the 
running system. This is done by retrieving the value of `NtBuildNumber`, and 
setting global variables accordingly (some critical structures used by the 
driver differs between systems). For example, `_OBJECT_TYPE` changed in 
Windows Vista SP1. Here are the differences: 

```c
// _OBJECT_TYPE in Vista SP1
struct _OBJECT_TYPE
{
    struct _LIST_ENTRY TypeList;                                       //0x0
    struct _UNICODE_STRING Name;                                       //0x8
    VOID* DefaultObject;                                               //0x10
    ULONG Index;                                                       //0x14
    ULONG TotalNumberOfObjects;                                        //0x18
    ULONG TotalNumberOfHandles;                                        //0x1c
    ULONG HighWaterNumberOfObjects;                                    //0x20
    ULONG HighWaterNumberOfHandles;                                    //0x24
    struct _OBJECT_TYPE_INITIALIZER TypeInfo;                          //0x28
    struct _ERESOURCE Mutex;                                           //0x78
    struct _EX_PUSH_LOCK TypeLock;                                     //0xb0
    ULONG Key;                                                         //0xb4
    struct _EX_PUSH_LOCK ObjectLocks[32];                              //0xb8
    struct _LIST_ENTRY CallbackList;                                   //0x138
}; 

// _OBJECT_TYPE in Win2003 SP2
struct _OBJECT_TYPE
{
    struct _ERESOURCE Mutex;                                           //0x0
    struct _LIST_ENTRY TypeList;                                       //0x38
    struct _UNICODE_STRING Name;                                       //0x40
    VOID* DefaultObject;                                               //0x48
    ULONG Index;                                                       //0x4c
    ULONG TotalNumberOfObjects;                                        //0x50
    ULONG TotalNumberOfHandles;                                        //0x54
    ULONG HighWaterNumberOfObjects;                                    //0x58
    ULONG HighWaterNumberOfHandles;                                    //0x5c
    struct _OBJECT_TYPE_INITIALIZER TypeInfo;                          //0x60
    ULONG Key;                                                         //0xac
    struct _ERESOURCE ObjectLocks[4];                                  //0xb0
}; 
```

The offset of `TypeList` in these two versions differs by an offset of `0x38`
bytes. The driver will adjust its code regarding the Windows version.

Using these checks, we can guess that the driver is able to run on the
following list of Windows versions:

- Windows 2000
- Windows XP
- Windows Server 2003
- Windows Vista
- Windows Vista 1 
- Windows Vista 2

![Supported_WinVersions](../../../../static/APT41_driver_analysis/Windows_Versions.png)

We can notice that the code adjustment for the offset of `TypeList` in not 
properly handled in Windows Vista. Running this driver on that system probably
leads to a BSOD because of that.

Shortly after, the driver retrieves its name (function at `0x10e72`) and hash 
it with the following algorithm (function at `0x10df6`).

```py
sum = 0
for c in name:
    sum = (sum * 3) + (sum >> 1) + c.upper()
sum %= 0x25
```

### Hooking

Everything is set up for the driver to makes hooking works. The driver will 
hook 3 differents functions to do its job.

- `IPSecHandlePacket`
- `NtDeviceIoControlFile`
- `NtSetQuotaInformationFile`

#### IPSecHandlePacket

This hook is probably the trickiest, as IPSecHandlePacket is not an exported
function easily accessible. Its name was leaked in 2020 with the Windows XP 
leak.

Let's break this, step by step. The driver starts by checking the Windows system
 version yet again. It is important to note that this hook is performed only 
 on Windows XP and Windows Server 2003. All other supported 
 vestions are ignored. It then looks for the driver named `ipsec.sys` in memory,
 and retrieves its base address and size (function at `0x117bc`). Then, it looks
 for two specific patterns in the loaded driver, in order to locate 
 `IPSecHandlePacket` (function at `0x118a0`). Finally, the driver creates a 
 shellcode, and write a trampoline in the target function to that shellcode 
 (function at `0x11b82`).

Here are more details. The driver lists all loaded modules by calling 
`ZwQuerySystemInformation` with 
`SystemInformationClass` equal to `SystemModuleInformation (0xb)`. The system
returns an array of `_RTL_PROCESS_MODULES` in a pool memory region previously 
allocated by the driver with the tag `Ipsp`.

The driver loops over the array, looking for `ipsec.sys` in the member 
`FullPathName`. When it does find it, it stores the members `ImageBase` and
`ImageSize`, and exits the function.

Now that the driver found `ipsec.sys` in memory, it will start looking for a
very specific pattern in it. The pattern is the following array of 5 bytes
`0x8b 0x4e 0x18 0x0f 0xc9`. By downloading `ipsec.sys` from a Windows XP
system, we quickly find the pattern.

```
		  LAB_00018a95                          XREF[1]:  00018a8b(j)  
00018a95    ff 0d 40        DEC           dword ptr [DAT_0001fc40]
            fc 01 00
		  LAB_00018a9b                          XREF[1]:  00018a93(j)  
00018a9b    ff 0d 38        DEC           dword ptr [DAT_0001fc38]
            fc 01 00
00018aa1    8b 4e 18        MOV           ECX,dword ptr [ESI + 0x18]
00018aa4    0f c9           BSWAP         ECX
00018aa6    b8 00 00        MOV           EAX,0xf0000000
            00 f0
```

The driver then retrieves the 4 bytes located just before the pattern. In our 
case this
is the following bytes `0x38 0xfc 0x01 0x00`. It then prepends the bytes
`0x39 0x3d`, and starts looking for this new pattern in `ipsec.sys`.

Again, there's only one occurence in the memory.

```
00012042    0f 85 9c        JNZ           LAB_000120e4
            00 00 00
		  LAB_00012048                          XREF[2]:  00010366(j), 0001202a(j)  
00012048    39 3d 38        CMP           dword ptr [DAT_0001fc38],EDI
            fc 01 00
0001204e    0f 84 3c        JZ            LAB_00010390
            e3 ff ff
00012054    33 c9           XOR           ECX,ECX
```

By looking at the Windows 2003 source code, we can guess that the piece of 
code above appears to be in the function `IPSecHandlePacket`.

The driver now has everything to prepare the hooking ! It allocated `0x2a` bytes 
using `ExAllocatedPoolWithTag` and the tag `Tag1`, then fill the memory with the
following shellcode.

```
0x0:    pushad 
0x1:    pushfd  
0x2:    mov eax, esp
0x4:    add eax, 4
0x7:    push    eax
0x8:    call    0xaaaaaaaa
0xd:    pop eax
0xe:    popfd   
0xf:    popad   
0x10:   nop 
0x11:   nop 
0x12:   nop 
0x13:   nop 
0x14:   nop 
0x15:   nop 
0x16:   nop 
0x17:   nop 
0x18:   nop 
0x19:   nop 
0x1a:   nop 
0x1b:   nop 
0x1c:   nop 
0x1d:   nop 
0x1e:   nop 
0x1f:   nop 
0x20:   nop 
0x21:   nop 
0x22:   nop 
0x23:   nop 
0x24:   push    0xbbbbbbbb
0x29:   ret 
```

The driver embed a LDE (Length Disassembler Engine) in order to compute the 
length of instructions in memory. The LDE is the function at `0x11a21`.

The driver uses the LDE to compute the length of the instructions located at the
address of the pattern it found in `IPSecHandlePacket`. It needs to find the
number of bytes to copy when it'll replace the bytes with its trampoline.
The trampoline is 5 bytes, so the driver is looking for the minimal number of
bytes greater or equal to 5 that will not end in the middle of an instruction.

For example, if you want to hook the code 

```
50              push eax
6878560000      push 0x5678
83c02a          add eax, 42
```

You need to copy 6 bytes instead of 5, overwise you'll not be able to execute
the second instruction in your hooking function.

In the driver's shellcode, the value `0xaaaaaaaa` is replaced with the address 
of the hook, the nop are filled with the copied bytes (that were replaced by
the trampoline), and `0xbbbbbbbb` is replaced with the address right after the 
trampoline. Finally, a small piece of code is added after the
stolen instruction to perform a check on the return of the hooking function.

This gives the following shellcode.

```
0x0:    pushad
0x1:    pushfd  
0x2:    mov eax, esp
0x4:    add eax, 4
0x7:    push    eax
0x8:    call    0x11984                 // This is the call to the hook
0xd:    pop eax
0xe:    popfd   
0xf:    popad
0x10:   cmp dword ptr [0x1fc38], edi    // Copied instruction (erased by trampoline)
0x16:   je  0x1a
0x18:   cmp eax, edi                    // Check on the return value of the hook
0x1a:   nop 
0x1b:   nop 
0x1c:   nop 
0x1d:   nop 
0x1e:   nop 
0x1f:   nop 
0x20:   nop 
0x21:   nop 
0x22:   nop 
0x23:   nop 
0x24:   nop 
0x25:   push    0x1204e                 // Return to the original function
0x2a:   ret 
```

On the other hand, the driver write the trampoline in `ipsec.sys` code. To do it,
it changes the bit `Write Protect` of the control register
`CR0` to 0. According to wikipedia, when this bit is set, the CPU can't write 
to read-only pages when privilege level is 0.

The hook function is pretty simple. Its parameter is an array of registers, 
that is the result of the `pushad` instruction at the very beginning of the 
shellcode. The hook checks for the value of `*(ebp + 8)`, which is, because of 
the trampoline, the first argument of the function `IPSecHandlePacket`. By
looking at the Windows 2003 source code, we can notice that the first parameter
of this function is a `IN PUCHAR pIPHeader` which is basically a raw IP header.
The hook function looks for `*(pIPHeader + 0x10)` and `*(pIPHeader + 0xc)`,
which are respectively the values of `IpDest` and `IpSrc` in the header, 
and compare them with some values in its `.data` section. 
It then sets `eax` accordingly.

As `edi` is equal to 0 at the beginning of the shellcode, the check at `0x18` on
the returned value will set the `ZF (ZeroFlag)` if the `IpDest` or `IpSrc` match
a certain value. Looking at the Windows 2003 source code again, we can see that
in that case, `IPSecRecvPacket` and `IPSecSendPacket` are never reached.

This means that this hook acts like a very simple and very low level firewall 
on the system. If an IP address is added (we'll see later how) to the blocklist,
the hook will reject every packet sending to or receiving from to this address.

#### NtDeviceIoControlFile

Before starting to hook `NtDeviceIoControlFile`, the driver initialize a mutex
in the function at `0x11cdc`, using `KeInitializeMutex`.

![Init mutex](../../../../static/APT41_driver_analysis/init_mutex.png)

The driver retrieves the address of `NtDeviceIoControlFile` from its 
imports and starts to look for a pattern `0x5d 0xc2 0x28 0x00` around this 
address.

Here's the disassembly of `NtDeviceIoControlFile` on Windows XP. 

```
nt!NtDeviceIoControlFile:
8057924a 8bff            mov     edi,edi
8057924c 55              push    ebp
8057924d 8bec            mov     ebp,esp
8057924f 6a01            push    1
80579251 ff752c          push    dword ptr [ebp+2Ch]
80579254 ff7528          push    dword ptr [ebp+28h]
80579257 ff7524          push    dword ptr [ebp+24h]
8057925a ff7520          push    dword ptr [ebp+20h]
8057925d ff751c          push    dword ptr [ebp+1Ch]
80579260 ff7518          push    dword ptr [ebp+18h]
80579263 ff7514          push    dword ptr [ebp+14h]
80579266 ff7510          push    dword ptr [ebp+10h]
80579269 ff750c          push    dword ptr [ebp+0Ch]
8057926c ff7508          push    dword ptr [ebp+8]
8057926f e8be6f0000      call    nt!NtWriteFile+0x3340 (80580232)
80579274 5d              pop     ebp
80579275 c22800          ret     28h
```

We can see the pattern at the very end of the function. Once the driver found 
this pattern, it saves the address of the original call then call the function 
at `0x1111a` with 3 parameters:

- The hook function.
- The address of `IoAttachDeviceByPointer`.
- A pointer to an address that will be written by the function. 

The function at `0x1111a` has one purpose: finding a code cave to place the
jump to the hook function.

It achieves this by looking for the pattern `0xcccccccc` around the address
passed as the second argument (in our case `IoAttachDeviceByPointer`). Once it
find the pattern, it will overwrite the `0xcccccccc` with the following
trampoline.

```
0x0:    68XXXXXXXX      push addr 
0x5:    c3              ret 
```

The interesting trick here is the way the driver copy the trampoline in memory, 
as the memory is marked as `READ_ONLY`. The driver will use `Memory Descriptor
List` to mark the memory as writable. This trick can be find on the internet
and involves calling several APIs such as `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`,
and `MmMapLockedPagesSpecifyCache`. To make it simple, let's say that changing 
memory rights involves creating a `Memory Descript List` using `IoAllocateMdl`, 
then the call to `MmBuildMdlForNonPagedPool` is used to fill the MDL with the 
physical pages number. The memory rights are changed by setting the bit 
`MDL_MAPPED_TO_SYSTEM_VA` to the member `MdlFlags` of the `MDL` structure.
Finally, `MmMapLockedPagesSpecifyCache` is called to commit the change to 
the virtual memory.

![Mdl trick](../../../../static/APT41_driver_analysis/mdl_trick.png)

This method is used in several places in the driver's code, mostly as a `memcpy`
alternative on read-only memory.

The driver finally update the original call in `NtDeviceIoControlFile` to the 
newly created trampoline.

So here's quick resume of the `NtDeviceIoControlFile` hook:

The driver starts by finding the address of a call to a function in the code of 
`NtDeviceIoControlFile`. The address of this call is saved, and the driver looks
for a code cave around `IoAttackDeviceByPointer`. Once it's find, it writes 
the trampoline in the code cave using the `Memory Descriptor List` trick, as the 
memory is marked as `READ_ONLY`. Finally, it overwrite the call to a function in 
`NtDeviceIoControlFile` by a call to the trampoline.

Let's have a look at the hook function. 

The function is located at `0x10ace` and starts by calling the original function.
It then checks for the Windows version, and calls the function at `0x116a6` if 
the system is prior to Windows Vista. It calls `0x11702` otherwise.

These two functions are very similar, and have been written to achieve the same 
goal on different Windows systems.

- For XP, 2003 and 2000, the function checks that the `IoControlCode` argument
of the function is equal to `0x120003`, and that the `InputBufferLength` equals
`0x24`.

- For Vista, the `IoControlCode` must equal `0x12001b`, and `InputBufferLength`
must equal `0x3c`.

Some checks are performed on `InputBuffer` inside both of the functions. 

These functions check the conditions for the "real" hook function to be called.
If the parameters do not pass the checks, the function return without doing
anything.

The value `0x120003` corresponds to ioctl `IOCTL_TCP_QUERY_INFORMATION_EX`, 
which is described on msdn as an operation that retrieves information from the 
TCP/IP driver.

According to microsoft, the input buffer must be a pointer to the following
structure

```c
typedef struct tcp_request_query_information_ex_w2k 
{
	TDIObjectID ID;
	uchar       Context[CONTEXT_SIZE];
} TCP_REQUEST_QUERY_INFORMATION_EX_W2K, *PTCP_REQUEST_QUERY_INFORMATION_EX_W2K;
```

where `CONTEXT_SIZE` is 16, and `TDIObjectID` is the following.

```c
typedef struct TDIObjectID 
{
	TDIEntityID toi_entity;
	ulong       toi_class;
	ulong       toi_type;
	ulong       toi_id;
} TDIObjectID;

typedef struct TDIEntityID 
{
	ulong tei_entity;
	ulong tei_instance;
} TDIEntityID;
```

As `SIZEOF(TCP_REQUEST_QUERY_INFORMATION_EX_W2K)` equals `0x24`. We now
understand the meaning of the inital length check, and several others ( 
`toi_entity.tei_entity` must equals `0x400` which is `CO_NL_ENTITY`, and 
`toi_id` must equal `0x100`, `0x102` or `0x110`. These enums aren't well
documented, but are known to format the structure of output buffer).

I will not go into details of the hook, as most of the code is basically some
multiple version of the same operation, duplicated because of the different
structure an output buffer can be, or because of the different Windows versions 
supported.

The goal is simple: hide specific communication from the running system by
removing the entries in the table when a query is made. The hook function loops
over the output buffer, looking for specific IPs and ports, and will remove
these entries from the array when they are found. 
For example, running the `netstat` command will internaly call 
`NtDeviceIoControlFile` with `IOCTL_TCP_QUERY_INFORMATION_EX` as `IoControlCode`
, and the connections will not appear. Once again, these IPs and ports
aren't hard-coded, but are managed from userland using the last hook the driver
perform: the `NtSetQuotaInformationFile` hook.

#### NtSetQuotaInformationFile 

This hook is the most important one, as it allows controls over the driver from 
userland.

Its setup is mostly the same as `NtDeviceIoControlFile`. This time, the driver 
looks for a code cave around `IoRaiseHardError` and overwrite `READ_ONLY`
memory using the same `MDL` trick.

Once again, let's have a look at `NtSetQuotaInformationFile` on Windows XP.

```
nt!NtSetQuotaInformationFile:
8057b7de 8bff            mov     edi,edi
8057b7e0 55              push    ebp
8057b7e1 8bec            mov     ebp,esp
8057b7e3 6a00            push    0
8057b7e5 ff7514          push    dword ptr [ebp+14h]
8057b7e8 ff7510          push    dword ptr [ebp+10h]
8057b7eb ff750c          push    dword ptr [ebp+0Ch]
8057b7ee ff7508          push    dword ptr [ebp+8]
8057b7f1 e8cc5c0000      call    nt!NtWriteFile+0x45d0 (805814c2)
8057b7f6 5d              pop     ebp
8057b7f7 c21000          ret     10h
```

The driver is looking for the sequence `0x5d 0xc2 0x10 0x00` which we can find
at the end of the function, and will replace the destination of the call just 
before. On Windows Vista, it searches for `0x8b 0xec 0x5d 0xe9`. 

Let's analyze the hook function. We can notice that the function will enter the
hook only if the first parameter (`HANDLE FileHandle`) equals `-2`. If not, the 
normal operation is performed.

![NtSetQuotaInformationFile hook](../../../../static/APT41_driver_analysis/NtSetQuota.png)

The driver simply add an operation for an existing system call. This new 
operation can perform the 3 following tasks: 

- Add an IP and a port to hide from the system (task `0x1000`)
- Hide the driver (task `0x2000`)
- Add an IP to block in firewall (task `0x4000`).

The first 4 bytes of the `Buffer` parameter indicates which task to perform. 
Then the 4 next bytes indicates the length of the options. Then the buffer 
contains `N` options describing informations for the different tasks.

For example, if we want to hide from the system the connection from 
`192.168.1.10` on port `4444`, we can call the newly system call with the 
following arguments `NtSetQuotaInformationFile(-2, IoStatusBlock, Buffer, 14);` 
with buffer formatted as below.

![buffer](../../../../static/APT41_driver_analysis/task1000.png)

The task `0x2000` does not take any option as parameter, and will simply remove 
the driver from different linked list in memory (`InLoadOrderLinks`, 
`_OBJECT_TYPE->TypeList`, `\\Driver` directory's object, ...).

The task `0x4000` helps adding or removing entries for the firewall database.
The entries have some uncompleted members, as they can be set but are not used
by the firewall. For example, it's possible to specify a port to the firewall,
but it will not be used. The firewall will block the corresponding IP address on
any ports.

Here are the buffer format for adding the entry `192.168.1.10` to the block 
entry of the firewall.

![add_entry](../../../../static/APT41_driver_analysis/add_entry.png)

And for removing an entry.

![remove_entry](../../../../static/APT41_driver_analysis/remove_entry.png)


## Conclusion

This sample was really cool to look at, even if it's small (~12Kb), old (2011)
, and not obfuscated at all, somes of the technics used were pretty interesting. 
The driver was clearly in development at that time, as we noticed the unused 
members of the firewall's block entry structure.

Feel free to contact me if you have some questions about it :).
