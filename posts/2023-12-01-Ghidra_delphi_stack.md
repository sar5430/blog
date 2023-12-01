# Patching Delphi stack cleaning in Ghidra

If you have ever analyzed a Delphi binary using Ghidra, you might have noticed the failure of the decompiler. As shown in the image below, the compiler tends to emit a lot of variables named like "stack0xffffffc4." This partially breaks the decompiler output and is not really readable at all.

![decompiler fail](/static/delphi_stack_patch/decompiler_fail.png)

All of this comes from the way Delphi binaries prepare the stack for local variables. The prologue of a function looks like this:

![delphi prologue](/static/delphi_stack_patch/delphi_prologue.png)

In this example, the program pushes 0x3b times two null DWORD on the stack. Replacing those instructions with a simple "sub esp, 0x1d8" (0x1d8 = (4 + 4) * 0x3b) is enough to clean the decompiler output:

![delphi prologue patched](/static/delphi_stack_patch/delphi_prologue_patch.png)

![decompiler after patch](/static/delphi_stack_patch/decompiler_after_patch.png)

I did not develop the script that patch all functions' prologues, but it shouldn't be too complex. 

