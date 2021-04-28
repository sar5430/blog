## Analysis of a nanocore loader

Recently I analysed a malware I found on [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/). Its SHA256 is `fb01157b437b00f34999faa320bb55c8e44bdbb415e9a15503035bfe0e1d40d6` and the binary is marked as Nanocore on the website.

This blog post won't cover the analysis of the final nanocore payload, as it's already pretty well described on the internet.

Running `file` on the binary returns the following

```
sar@pc:~/nanocore_loader$ file fb01157b437b00f34999faa320bb55c8e44bdbb415e9a15503035bfe0e1d40d6.exe 
fb01157b437b00f34999faa320bb55c8e44bdbb415e9a15503035bfe0e1d40d6.exe: PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive
```

Nullsoft Installer is an installer that allows to write a small script to describe how the files will be installed on the system. Old versions of 7zip helps us to extract the script and the installed files.

![7zip1](../../../../static/nanocore_loader_analysis/7zip1.png)
![7zip2](../../../../static/nanocore_loader_analysis/7zip2.png)

The binary contains 4 files: 
- `[NSIS].nsi` which is the Nullsoft script
- `xavbedcnsrtbhix` which is a 12Kb file of encrypted data
- `nejus0or2e4wbg8rhay` which is a 277Kb file of encrypted data
- `$PLUGINSDIR/xktfu.dll` which is a 5Kb dll

Here's the content of the script:

```
; NSIS script NSIS-3 BadCmd=11
; Install

SetCompressor zlib

; --------------------
; HEADER SIZE: 3073
; START HEADER SIZE: 300
; MAX STRING LENGTH: 1024
; STRING CHARS: 755

OutFile [NSIS].exe
!include WinMessages.nsh



; --------------------
; LANG TABLES: 1
; LANG STRINGS: 47

Name "Template Method Pattern"
BrandingText "Nullsoft Install System v3.06.1"

; LANG: 1033
LangString LSTR_0 1033 "Nullsoft Install System v3.06.1"
LangString LSTR_1 1033 "$(LSTR_2) Setup"
LangString LSTR_2 1033 "Template Method Pattern"
LangString LSTR_5 1033 "Can't write: "
LangString LSTR_8 1033 "Could not find symbol: "
LangString LSTR_9 1033 "Could not load: "
LangString LSTR_17 1033 "Error decompressing data! Corrupted installer?"
LangString LSTR_21 1033 "Extract: "
LangString LSTR_22 1033 "Extract: error writing to file "
LangString LSTR_24 1033 "No OLE for: "
LangString LSTR_25 1033 "Output folder: "
LangString LSTR_29 1033 "Skipped: "
LangString LSTR_30 1033 "Copy Details To Clipboard"
LangString LSTR_36 1033 "Error opening file for writing: $\r$\n$\r$\n$0$\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or$\r$\nIgnore to skip this file."
LangString LSTR_37 1033 Custom
LangString LSTR_38 1033 Cancel
LangString LSTR_39 1033 ": Installing"
LangString LSTR_40 1033 "Show &details"
LangString LSTR_41 1033 Completed
LangString LSTR_42 1033 "< &Back"
LangString LSTR_43 1033 "&Next >"
LangString LSTR_44 1033 "Click Next to continue."
LangString LSTR_45 1033 ": Completed"
LangString LSTR_46 1033 &Close


InstType $(LSTR_37)    ;  Custom
InstallDir $TEMP
; wininit = $WINDIR\wininit.ini


; --------------------
; PAGES: 2

; Page 0
Page instfiles
  CompletedText $(LSTR_41)    ;  Completed
  DetailsButtonText $(LSTR_40)    ;  "Show &details"

/*
; Page 1
Page COMPLETED
*/


; --------------------
; SECTIONS: 1
; COMMANDS: 23

Function .onInit
  SetOutPath $INSTDIR
  File xavbedcnsrtbhix
  File nejus0or2e4wbg8rhay
  xktfu::Cgrlcpdlsle
    ; Call Initialize_____Plugins
    ; SetOverwrite off
    ; File $PLUGINSDIR\xktfu.dll
    ; SetDetailsPrint lastused
    ; CallInstDLL $PLUGINSDIR\xktfu.dll Cgrlcpdlsle
FunctionEnd


Section ; Section_0
SectionEnd


/*
Function Initialize_____Plugins
  SetDetailsPrint none
  StrCmp $PLUGINSDIR "" 0 label_19
  Push $0
  SetErrors
  GetTempFileName $0
  Delete $0
  CreateDirectory $0 ; !!!! Unknown Params:  $0 "" ProgramFilesDir   ; 144 0 1
  IfErrors label_20
  StrCpy $PLUGINSDIR $0
  Pop $0
label_19:
  Return

label_20:
  MessageBox MB_OK|MB_ICONSTOP "Error! Can't initialize plug-ins directory. Please try again later." /SD IDOK
  Quit
FunctionEnd
*/



; --------------------
; UNREFERENCED STRINGS:

/*
17 CommonFilesDir
32 "C:\Program Files"
49 $PROGRAMFILES
53 "$PROGRAMFILES\Common Files"
70 $COMMONFILES
*/
```

The important part of the script is the function `.onInit` which basically does 4 things: 
- Set the output directory to `%APPDATA%\Local\Temp`
- Write `xavbedcnsrtbhix` to that directory
- Write `nejus0or2e4wbg8rhay` to that directory
- Execute function `Cgrlcpdlsle` of the plugin `xktfu.dll`

Let's have a look at this `xktfu.dll`.

## xktfu.dll

The library is pretty small, and contains only 2 functions (including the exported one `Cgrlcpdlsle`). 
`Cgrlcpdlsle` starts by performing an anti-debug and an anti-emulation check. The anti-debug is a simple call to `IsDebuggerPresent`, and the anti-emulation is a call to a function at `0x10001000` that will perform a loop from `0` to `0x75861fef`, in order to slow any eventual emulation.

Right after, the library maps the content of `xavbedcnsrtbhix` in memory, using `CreateFileW`, `GetFileSize`, `VirtualAlloc` and `ReadFile`, then decrypts it using a custom algorithm.

![Decompiled function](../../../../static/nanocore_loader_analysis/xktfu_decompiled.png)

By reimplementing the algorithm in python, we successfully decrypt the shellcode.

```py
def ROR(a, b):
    return ((a >> b) | (a << (8 - b))) & 0xff

f = open("./xavbedcnsrtbhix", "rb")

b = bytearray(f.read())

for i, c in enumerate(b):
    res = (c - 0x3d) & 0xff
    res ^= 7
    res = ROR(res, 1)
    res -= i
    res &= 0xff
    res = 255 - res
    res -= i
    res &= 0xff
    res ^= 0xd1
    res += i 
    res &= 0xff
    res ^= 0x93
    res += 0x44
    res &= 0xff

    b[i] = res
    print("{:x}".format(res), end='')

g = open("./xavbedcnsrtbhix_decrypted", "wb")
g.write(b)
```

The library then jumps on the very first byte of the shellcode.

## xavbedcnsrtbhix

The shellcode performs multiples operations in order to silently runs Nanocore. It achieves persistence on the system, decryption of the next stage (`nejus0or2e4wbg8rhay`), process hollowing, and uses many tricks to reach its goal.

### API resolving

The shellcode resolves the base address of `kernel32` by searching in the `InLoadOrderModuleList` list of the Process Environment Block. Then, it finds API addresses by comparing the hash of exports name with hardcoded values. 

The hashing algorithm is the following one:

```py
hash = 0x2326
for c in str:
	hash *= 0x21
	hash += c
	hash &= 0xffffffff	
```

Once `LoadLibraryW` has been resolved, the shellcode loads the library it needs, and resolves API addresses using the same method.

### Persistence

The shellcode achieves persistence by writing the original binary in the `Run` registry key (`HKCU\System\Software\Microsoft\Windows\CurrentVersion\Run`. In that particular shellcode, the operation fails because the API `PathAppend` is used to concatanate the `%APPDATA%` directory with a too long string. The last stage, Nanocore, successfully achieves this instead.

![Persistence](../../../../static/nanocore_loader_analysis/persistence.png)

### Custom RC4

The next stage is encrypted using a modified version of RC4, where the stream is xored with the RC4 key (`40fbb79f6fda487d8f06db1c793101bd`). The following python script decrypts the next stage.

```py
def KSA(key):
    keylength = len(key)

    S = []
    for i in range(256):
        S.append(i)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap

    for i in range(256):
        print(hex(S[i]), end=',')

    return S


def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap

        K = S[(S[i] + S[j]) % 256]
        yield K


def RC4(key):
    S = KSA(key)
    return PRGA(S)


if __name__ == '__main__':
    key = '40fbb79f6fda487d8f06db1c793101bd'.encode()
    f = open('./nejus0or2e4wbg8rhay', 'rb')
    b = bytearray(f.read())

    keystream = RC4(key)
    for i, _ in enumerate(b):
        b[i] ^= next(keystream) ^ key[i % len(key)]

    g = open('./nejus0or2e4wbg8rhay_decrypted', 'wb')
    g.write(b)
```

### Process Hollowing

In order to execute the next stage, the shellcode performs process hollowing. It creates another process (in a suspended state) of the original binary, then replaces all the binary sections using the following list of syscalls:
- `NtMapViewOfSection`
- `NtUnmapViewOfSection`
- `NtWriteVirtualMemory`
- `NtCreateSection`
- `NtResumeThread`

![Injection](../../../../static/nanocore_loader_analysis/injection.png)

I will not explain in details how the process hollowing is done, as it's well explained everywhere on the internet.

### Direct syscall

The shellcode uses the instructions `sysenter` (on a 32 bit system) and `syscall` (on a 64 bit system) to directly call the syscalls listed above. The syscalls numbers aren't hardcoded, instead, the shellcode manually map `ntdll.dll` in memory, finds the corresponding wrapper to the corresponding syscalls using the hashing method described above, then steals the syscall number by looking for `mov eax, XX` instructions. 

On a 64 bit system, as the process is a 32 bit one, the shellcode switch to 64 bit mode using the instruction `retf`

![heaven's gate](../../../../static/nanocore_loader_analysis/heaven_gate.png)

## nejus0or2e4wbg8rhay

The next stage is the one executing the Nanocore RAT. It contains the RAT as its only resource. It will simply loads the resource and prepare the execution. As Nanocore is a .NET binary, the binary need to initialize the .NET framework to call .NET functions natively. This initialisation is done using COM interfaces, and is partially explained in the [msdn](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/01918c6x(v=vs.100)).

![load_resource](../../../../static/nanocore_loader_analysis/load_resource.png)

## IOCs

File | Sha256
----------- | -----------
original_file | fb01157b437b00f34999faa320bb55c8e44bdbb415e9a15503035bfe0e1d40d6
xktfu.dll | 9c94096638fbad8f4f41e33012437c149ecd4ab055e56fddacbd35cbcb2adcb6
xavbedcnsrtbhix | b4bc8bcafc597734dff776d588dcf7f82c6ba6a1ba96f04a0b384b3f30aa4e24
xavbedcnsrtbhix_decrypted | eed66b195ab779d5367bfbe92feeafe5db8ec13e8d657a8417c7d9e07680315b
nejus0or2e4wbg8rhay | af23271a22b4657cf3765bb7a1a40e130cb9145d4549d004cf9baf1c4cb854ca
nejus0or2e4wbg8rhay_decrypted | 7c906c16071a4ebcafb881c4b9c708251e12ce4c45f128b8b62df520463e9c45
nanocore.exe | 9ce9bdddbd6ebdd12d1b2234e60f0eb23a72f24b9419ef1bc47267f2c27da26d

## Resources

[Here](../../../../static/nanocore_loader_analysis/xavbedcnsrtbhix_decrypted.gzf)'s the Ghidra zip file of `xavbedcnsrtbhix_decrypted`
