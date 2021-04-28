## Shared page via pte overwrite

Recently I wanted to implement another method of code/data injection into a 
running linux process. 

As you probably already know, each linux process have its own address space, 
in a way that two different process can have totally different data at the same 
address. This has been made possible thanks to pagination and page tables. If 
you're not familiar with this, I recommend you to read 
[this](https://www.triplefault.io/2017/07/introduction-to-ia-32e-hardware-paging.html) great article.

To make it short and simple, each linux process have a page table located 
somewhere in memory. This table makes translation between process' virtual 
addresses and physical addresses possible.

An interesting method to inject data into a running process is to modify its 
page table. If we manage to change a page table entry (pte) in the target process' 
page table, then an access to the virtual address corresponding to that entry will 
translate to a different physical address.

Suppose we have a process, running the following C code:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main()
{
    int* addr = 
        (int*)
        mmap(
            (void*)0x666000, 
            0x1000, 
            PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANON, 
            0, 
            0);

    printf("%p\n", addr);
    *addr = 0xdeadbeef;

    while(1)
    {
        printf("%x\n", *addr);
        sleep(1);
    }

    return 0;
}
```

The program is simple, it allocates a page at address `0x666000`, then writes 
the value `0xdeadbeef` into the very first 4 bytes of the new region. It then 
reads the value each second. Let's call this process our target process.

Let's create another process, running the following C code: 

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main()
{
    int* addr = 
        (int*)
        mmap(
            (void*)0x666000, 
            0x1000, 
            PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANON, 
            0, 
            0);

    *addr = 0xcafebabe;

    fgetc(stdin);

    return 0;
}
```

This process (injector process) allocates a page at the same virtual address as our target
process. If we manage to replace the page table entry of the target process
with the page table entry of this process, then the target process will start
printing `0xcafebabe` each second. Even better, we would have a shared page 
between our two process that allow READ and WRITE access to the target from the injector.

Obviously, manipulating page table entries can't be done from userland, so I 
had to write a kernel module to achieve this. The kernel module exposes 2 ioctls,
the first one to perform the page table modification, and the second one to 
restore the original entry. In order to make the injection possible, both 
target and injector process must have the page to inject 
allocated at the same address.

Let's transform our injector code to this:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define GHOST _IOW ('a','a', struct ghost_map*)
#define UNGHOST _IOW ('a','b', int)

struct ghost_map                                                                
{                                                                               
	int pid;                                                                    
	int count_page;                                                             
	unsigned long *page_addr;                                                   
};
 
int* map()
{
    	int* addr = (int*)mmap((void*)0x666000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0);
    	printf("%p\n", addr);
    	*addr = 0xcafebabe;
    	return addr;
}
 
int main(int argc, char ** argv)
{
        int fd;
        int32_t value, number;

        unsigned long pa[] = {0x666000};

        int pid = strtol(argv[1], 0, 10);
		
		struct ghost_map to_map = 
        {
            .pid = pid, 
            .count_page = sizeof(pa) / sizeof(unsigned long), 
            .page_addr = pa
        };

        int* addr = map();
 
        printf("Opening Driver\n");

        fd = open("/dev/ghost_device", O_RDWR);

        if(fd < 0) {
	    printf("Cannot open device file...\n");
            return 0;
        }
 
        ioctl(fd, GHOST, &to_map); 

        fgetc(stdin);

        *addr = 0xfeedface;

        fgetc(stdin);

        ioctl(fd, UNGHOST, pid); 
 
        printf("Closing Driver\n");
        close(fd);
}
```

The code has been a bit modified to take a pid as `argv[1]`, and call our driver
to perform the injection. After the page table modification, the process waits
for an input, then changes the value in the shared page. It waits for another 
input, then restores the original entry in the target's page table.

Launching `./target` in a terminal, the process starts to write to stdout:

```
root@ubuntu:/mnt/hgfs/ghost/test_app# ./target 
0x666000
deadbeef
deadbeef
deadbeef
...
```

In another terminal, we can run the injector, then hitting `Enter` two times: 

```
root@ubuntu:/mnt/hgfs/ghost# ./test_app/injector `pidof target`
0x666000
Opening Driver


Closing Driver
``` 

We can see in the target's terminal that the value has been modified two times,
then came back to its original value.

```
root@ubuntu:/mnt/hgfs/ghost/test_app# ./target 
0x666000
deadbeef
deadbeef
deadbeef
deadbeef
deadbeef
deadbeef
cafebabe        <---- injector started 
cafebabe
feedface        <---- "Enter" pressed
feedface
deadbeef        <---- "Enter" pressed
deadbeef
deadbeef
deadbeef
deadbeef
deadbeef
^C
```

It becomes easy to hook code/data without even touching at the target process at all.

The code is available on my github.
