## Hooking toolsuite

I decided to post 3 programs I wrote as it could be useful for someone. I 
mostly use those programs to perform dll injection and hooking. It probably
contains bugs but it should works on 32 and 64 bits linux and windows systems.

Here's what the toolsuite contain: 

### hook

This is a really small codebase that helps me to make small patches to running
binaries. The code is platform independant. The .hpp should be enough to 
understand basic hooking. In case it's not, I've added a small Windows example.

### dll_loader

This is the first of these 3 tools I wrote. 
It simply perform an injection in a spawning process. It helped me a lot when 
I needed to write some binary instrumentation. I mostly use it to inject dlls
that perform patchs on the targeted binary.
It works as follows: the targeted process is created in a suspended state,
the instruction at entry point is patched in order to loop on itself, the 
context is changed ( no other thread is created ), the dll is injected ( in a 
traditional manner ), the entry point is restored, then the execution is 
resumed.  

`./loader.exe <bin_to_run.exe> <ARGS...> <dll_to_inject.dll>` will launch
`bin_to_run.exe` and inject `dll_to_inject.dll`

Of course, the dll must match the architecture ( 32/64 bits ) of the targeted
binary.

### manumap

This perform basically the same that does `dll_loader`, except that the 
injection is made into a running process. The program performs thread 
hijacking and manually load the dll in memory. It's pretty basic at the moment,
as the loader only perform relocations fixing, iat building and call TLS 
callbacks and entry point.

`./manumap.exe <PID> <dll_to_inject.dll>` will inject `dll_to_inject.dll` into
the targeted process.

Again, the dll must match the architecture.

*EDIT: I wrote manumap for linux too!*

### Code

I often use those tools, in order to perform simple binary instrumentation. 

Most of the time, I build a library performing the instrumentation using hooks 
with the help of `hook`, then inject the library using `manumap` or 
`dll_loader`. 

You can find those tools on my github.
