# Removing opaque predicates in ghidra

Recently I encountered a sample protected using CodeVirtualizer,
which is a software protector developed by [Oreans](https://www.oreans.com/CodeVirtualizer.php). 
It is well-known for its Virtual Machine obfuscation system, also used in one other of 
their famous product: Themida.

The sample was obfuscated with a ton of opaque predicates. Here's an example:

![Opaque predicate](/static/opaque_predicates/opaque_predicate.png)

The conditional jump in the picture above depends on the value of the EAX register. 
By revisiting how the value in EAX is generated, it becomes apparent that its value 
is entirely determined within the block. The value used for the comparison results 
from multiple arithmetic and bitwise operations, relying solely on the values of registers 
R13 and R10D, set to 0x7ffff55e and 0x1ffffd5, respectively, within the block.

To automatically remove those fakes conditional jumps, I decided to write a ghidra
script that would get the full advantage of Symbolic execution through the framework 
[Miasm](https://github.com/cea-sec/miasm).

The script is quite simple: it locates the cursor position and symbolically executes 
the program at that address. Whenever it encounters a conditional jump, it checks if 
both branches can be reached within the symbolic engine. If not, it simply patches the 
conditional jump with a NOP or a JMP.

The script is able to transform this function:

![Obfuscated function](/static/opaque_predicates/func_before.png)

Into this one:

![Function after removing opaque predicates](/static/opaque_predicates/func_after.png)

Currently, the script only supports X64 and X32-bit programs, but adding support for 
a new architecture should be straightforward as long as it is compatible with Miasm.

Here's the script:

```
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.bin_stream import bin_stream_container
from miasm.ir.symbexec import SymbolicExecutionEngine, get_block
from miasm.expression.expression import ExprInt, ExprAssign, ExprMem, ExprId, ExprLoc
from miasm.ir.ir import AssignBlock
from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_64
from miasm.expression.simplifications import expr_simp
from miasm.expression.expression_helper import possible_values

from ghidra.program.model.block import SimpleBlockModel
from ghidra.app.plugin.assembler import Assemblers
from ghidra.util.task import TaskMonitor

class FakeVirt():
    def __init__(self, mem_to_map):
        self.intervals = []
        for (addr, data) in mem_to_map:
            self.set(addr, data)
        self.intervals.sort()

    def max_addr(self):
        if not len(self.intervals):
            return 0
        return self.intervals[-1][0] + len(self.intervals[-1][1])

    def get(self, virt_start, virt_stop=None):
        for addr, data in self.intervals:
            if addr <= virt_start < addr + len(data):
                if virt_stop == None:
                    return data[virt_start - addr:]
                else:
                    if virt_stop - addr > len(data):
                        raise IOError("Out of range")
                    else:
                        return data[virt_start - addr:virt_stop - addr]
        raise IOError("Out of range")

    def set(self, rva, data):
        if rva < 0:
            raise IOError("Already in map ")

        for (a, d) in self.intervals:
            if a <= rva < a + len(d):
                raise IOError(f"Already in map {rva}")

        self.intervals.append((rva, data))

class FakeBin():
    def __init__(self, mem_to_map):
        self.virt = FakeVirt(mem_to_map)

class FakeCont(Container):
    def parse(self, mem_to_map):
        self.mem_to_map = mem_to_map
        self.fake_bin = FakeBin(self.mem_to_map)
        self._bin_stream = bin_stream_container(self.fake_bin)
        self._executable = None
        self._entry_point = 0

def get_address(address: int):
    return currentProgram().getAddressFactory().getAddress(str(hex(address)))

def run_symb_block(dis, lifter, ircfg, symb, addr: int):

    bl = dis.dis_block(offset=addr)
    lifter.add_asmblock_to_ircfg(bl, ircfg)

    next_addr = symb.run_block_at(ircfg, addr, step=False)

    return symb, next_addr

def get_block(addr):
    model = SimpleBlockModel(currentProgram())
    monitor = TaskMonitor.DUMMY
    block = model.getFirstCodeBlockContaining(get_address(addr), monitor)
    return block

def get_destinations(block):
    model = SimpleBlockModel(currentProgram())
    monitor = TaskMonitor.DUMMY
    destinations = model.getDestinations(block, monitor)

    dest_addr = []
    while destinations.hasNext():
        dest_addr.append(int(destinations.next().getDestinationAddress().toString(), 16))
    return dest_addr

def get_bytes(addr, sz):
    return bytes(map(lambda b: b & 0xff, getBytes(addr, sz)))

def is_opaque_predicate(next_addr, block_destinations):
    if len(next_addr) != 1 or len(block_destinations) != 2:
        return False

    if next_addr[0] not in block_destinations:
        return False

    return True

def patch_instr(block, next_addr):
    instr = getInstructionBefore(block.getMaxAddress())
    instr_str = instr.toString()
    jmp_dest = int(instr_str.split(' ')[-1], 16)
    orig_bytes = instr.getBytes()

    assembler = Assemblers.getAssembler(currentProgram())

    if jmp_dest == next_addr.__long__():
        new_bytes = assembler.assembleLine(instr.getAddress(), "JMP " + hex(jmp_dest))
        if len(new_bytes) <= len(orig_bytes):
            assembler.patchProgram(new_bytes, instr.getAddress())
        else:
            print("Cannot patch because new instruction is two long!")
            return False
    else:
        new_bytes = assembler.assembleLine(instr.getAddress(), "NOP")
        for i in range(len(orig_bytes)):
            assembler.patchProgram(new_bytes, instr.getAddress().add(i))

    return True

def get_memory():
    blocks = currentProgram().getMemory().getBlocks()
    mem = []
    for b in blocks:
        data_available = b.getData().available()
        addr = b.getStart()
        if data_available:
            data = get_bytes(addr, data_available)
            mem.append((int(addr.toString(), 16), data))
    return mem

def remove_opaque(arch, addr):
    loc_db = LocationDB()
    machine = Machine(arch)

    memory_blocks = get_memory()
    container = FakeCont(memory_blocks, loc_db)
    machine = Machine(arch)
    disassembler = machine.dis_engine(container.bin_stream, loc_db=loc_db)

    lifter = machine.lifter_model_call(loc_db)
    ircfg = lifter.new_ircfg()
    symb = SymbolicExecutionEngine(lifter)

    to_run = [(symb.get_state(), addr)]
    visited = []
    cpt_block_ran = 0
    while len(to_run):
        cpt_block_ran += 1

        if cpt_block_ran % 10 == 0:
            print(f'{cpt_block_ran} analyzed')

        symbols, addr = to_run.pop(0)
        print(f"Running at {addr:x}")
        visited.append(addr)

        block = get_block(addr)
        destinations = get_destinations(block)

        print(destinations)

        # First addr in destinations is always the "green" branch ?
        if len(destinations) == 0 or len(destinations) > 2:
            continue

        symb.set_state(symbols)

        symb, next_addr = run_symb_block(disassembler, lifter, ircfg, symb, addr)

        next_addrs_int = []
        print(f"next is {next_addr}")

        possible_dest = possible_values(next_addr)
        for dest in possible_dest:
            if dest.value.is_int():
                next_addrs_int.append(dest.value.__long__())
                if dest.value.__long__() not in visited:
                    print(f"adding 1 {dest.value.__long__():x}")
                    to_run = [(symb.get_state(), dest.value.__long__())] + to_run
            elif isinstance(dest.value, ExprLoc):
                if dest.value.is_loc():
                    addr_loc_key = loc_db.get_location_offset(dest.value.loc_key)
                    next_addrs_int.append(addr_loc_key)
                    if addr_loc_key and addr_loc_key not in visited:
                        print(f"adding 2 {addr_loc_key:x}")
                        to_run = [(symb.get_state(), addr_loc_key)] + to_run

        if is_opaque_predicate(next_addrs_int, destinations) and patch_instr(block, next_addr):
            print(f'Instruction patched at the end of block {addr:x}')


lang_id = currentProgram().getLanguageID().getIdAsString()
if lang_id.startswith('x86:LE:64:'):
    arch = "x86_64"
elif lang_id.startswith('x86:LE:32:'):
    arch = "x86_32"
else:
    print("Cannot do anything for this architecture")

addr = int(currentAddress().toString(), 16)

remove_opaque(arch, addr)
```

