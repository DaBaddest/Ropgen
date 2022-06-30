#!/usr/bin/python3
# TODO: Handle the condition when the tool was already run before, so as to 
# Make the tool faster for large binaries
import struct
import distorm3
import sys
import subprocess
import re
import os

def byte(v):
  if isinstance(v, int):
    return struct.pack("<B", v)
  return v

def word(v):
  if isinstance(v, int):
    return struct.pack("<H", v)
  return v

def dword(v):
  if isinstance(v, int):
    return struct.pack("<I", v)
  return v

def qword(v):
  if isinstance(v, int):
    return struct.pack("<Q", v)
  return v

class ROP:
  # We can manually set it too
  mode  = 64  # 32 or 64
  start = 0   # Start of text section or executable section
  end   = 0x1000  # End of text section or executable section
  va    = 0x400000

  decoding = None
  uniq = []
  functions_for_rop = []
  rop_chain = b""
  rop_chain_text = "rop_chain  = ''\n"

  def __init__(this, binary_name):
    this.binary_name = binary_name
    this.set_mode()
    this.get_offsets()

  def set_mode(this):
    '''Getting the arch of file'''
    # Currently can be 32bit or 64bit ELF File
    if this.mode is None:
      this.print_warning("Mode not set. Finding Mode")
      P = subprocess.Popen(["file", this.binary_name],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
      ret, _ = P.communicate()
      ret = ret.decode('charmap')

      if "elf" not in ret.lower():
        print_error("ERROR: Unknown Architecture")
        print_error("This tool currently supports only ELF Files")
        exit()

      this.mode = int(ret.split("ELF ")[1].split("-bit")[0])
    
    if 32 == this.mode:
      this.decoding = dword
      this.print_info("Mode: 32-bits")
      this.mode = distorm3.Decode32Bits

    if 64 == this.mode:
      this.decoding = qword
      this.print_info("Mode: 64-bits")
      this.mode = distorm3.Decode64Bits

  def get_offsets(this):
    '''Getting Virtual Address and File offset of .text section'''

    # If this.va is set manually
    if this.va and this.start:
      this.va -= this.start

    if this.start is None or this.end is None:
      this.print_warning("Finding the start and end offsets")

      P = subprocess.Popen(["readelf", "-SW", this.binary_name],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

      ret, _ = P.communicate()
      ret = ret.decode('charmap')

      ret = ret.replace("[ ", "[").splitlines()

      for i in range(len(ret)):
        if ".text" in ret[i]:
          this.start = ret[i]  # Start of text section
          this.end = ret[i+1]  # End of text section
          break

      this.start = this.start.strip()

      tmp = this.start.split()
      this.start = int(tmp[4], 16)
      this.va = int(tmp[3], 16)

      # The reason is when decoding we add the this.start again
      this.va -= this.start

      this.end = this.end.strip()
      tmp = this.end.split()
      this.end = int(tmp[4], 16)

    this.print_info(f"Start: {this.va + this.start:#08x}")
    this.print_info(f"End:   {this.va + this.end:#08x}")
    this.print_info(f"VA:    {this.va:#08x}\n")


  def MakeFunction(this, address, inst, pattern):
    if distorm3.Decode32Bits == this.mode:
      decoding = "dword"
    if distorm3.Decode64Bits == this.mode:
      decoding = "qword"

    regs = ""
    to_write = f"#{address} {inst}\n"
    if "pop" in pattern:
      # Scarry string parsing
      funcName = ''.join(inst.split("; "))
      funcName = '_'.join(funcName.split("pop ")[1:]).replace("ret", "")
      regs = funcName.split("_")

      params = ''.join([f"{i} = 0, " for i in regs])[:-2]

      to_write += f"def pop_{funcName}({params}):\n"

    # Special case for ret2csu
    elif "mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12+rbx*8]" ==\
          inst:
      to_write += "def ret2csu():\n"

    elif "mov " in pattern:
      inst = inst.replace("; ret", "").replace("mov ", "")
      inst = inst.replace("[", "").replace("]", "")
      inst = inst.split(", ")

      funcName = '_'.join(inst)

      to_write += f"def write_into_{funcName}():\n"
      # print(to_write)

    else:
      # Yet to be implemented stuff
      return ""

    to_write += f"  return {decoding}({address[:-1]})"

    if regs:
      for reg in regs:
        to_write += f" + {decoding}({reg})"

    return to_write

  def check_interesting(this, address, inst):
    inst = inst.lower()
    if inst in this.uniq:
      return False

    patterns32Bit = [r"(pop e.*?; )+ret",
                     r"(push e.*?; )+ret",
                     r"mov \[e\w+\], e..; ret",
                    ]

    patterns64Bit = [r"(pop r\w+; )+ret",
                     r"(push r\w+; )+ret",
                     r"mov \[r\w+\], [r,e]\w+; ret",
                     r"mov rdx, r15; mov rsi, r14; mov edi, r13d;\
                       call qword \[r12\+rbx\*8\]",
                     ]

    if distorm3.Decode32Bits == this.mode:
      patterns = patterns32Bit
    elif distorm3.Decode64Bits == this.mode:
      patterns = patterns64Bit

    if not patterns:
      return None

    for pattern in patterns:
      if re.match(pattern, inst):
        this.uniq.append(inst)
        return this.MakeFunction(address, inst, pattern)

  def get_gadgets(this):
    with open(this.binary_name, 'rb') as fp:
      data = fp.read()

    gadget2 = []
    off = [] # address of gadget
    for i in range(this.start, this.end):
      lst1 = []
      lst2 = []
      flag = 0
      # change i+20 if gadgets not found
      decoded = distorm3.Decode(this.va+i, data[i:i+20], this.mode) # XXX
      addr = []
      inst = []
      tmp_address = None
      for elem in decoded:
        addr.append(elem[0])
        inst.append(elem[2].lower())
      for x, y in zip(inst, addr):
        if tmp_address is None:
          tmp_address = f"{y:#08x}"
        lst2.append(x.lower())

        # XXX Check this
        if "ret" in x:
          flag = 1
          break
        if re.match(r"call ([q|d]word )?\[?[re][abcds189].*?\]", x):
          flag = 1
          break

      if flag:
        # print(lst1)
        # print(lst2)
        # input()
        tmp2 = "; ".join(lst2)
        if "db " in tmp2:     # If the disassembly process failed
          continue
        if tmp2 in gadget2:  # Checking if its not already found
          continue
        off.append(tmp_address)
        gadget2.append(tmp2) # gadgets in a single line

    return off, gadget2

  def print_error(this, s):
    print(f"\x1b[31m[!] {s}\x1b[0m")

  def print_info(this, s):
    print(f"\x1b[32m[*] {s}\x1b[0m")

  def print_warning(this, s):
    print(f"\x1b[33m[*] {s}\x1b[0m")


  def initialize(this):
    # gadgets is multilined output, gadgets2 is single line output
    offsets, gadgets = this.get_gadgets()
    gad_count = 0
    to_write = ''

    width = os.get_terminal_size()[0]
    interesting_gadgets = []

    # Dynamically create python functions
    

    for address, gadget in zip(offsets, gadgets):
      to_write += f"{address} {gadget}\n"
      funcDef = this.check_interesting(address, gadget)
      if funcDef:
        this.functions_for_rop.append([funcDef])
        interesting_gadgets.append(f"{address} {gadget}")
      # print()
      gad_count += 1

    this.print_info("Total %i gadgets found" % gad_count)
    this.print_warning('Gadgets also written to "gadgets.asm" file')

    with open("gadgets.asm", "w") as fp:
      fp.write(("Total %i gadgets found\n" % gad_count) + to_write)


    tmp = '\n'.join([''.join(i) for i in this.functions_for_rop]).splitlines()
    # print(tmp)
    if len(tmp) > 0:
      fname = "useful_functions.py"
      this.print_info(f'Writing Useful Function to "{fname}" file')
      with open(fname, 'w') as fp:
        # Writing helper functions to file
        fp.write("import struct\n")

        fp.write('def byte(v):\n  if isinstance(v, int):\n')
        fp.write('    return struct.pack("<B", v)\n  return v\n')

        fp.write('def word(v):\n  if isinstance(v, int):\n')
        fp.write('    return struct.pack("<H", v)\n  return v\n')

        fp.write('def dword(v):\n  if isinstance(v, int):\n')
        fp.write('    return struct.pack("<I", v)\n  return v\n')

        fp.write('def qword(v):\n  if isinstance(v, int):\n')
        fp.write('    return struct.pack("<Q", v)\n  return v\n\n')

        for func in this.functions_for_rop:
          fp.write("\n\n".join(func) + "\n\n")

    if interesting_gadgets:
      this.print_info("****List Of Interesting Gadgets****")
      for i in interesting_gadgets:
        this.print_info(i)


  def padding(this, length):
    '''For padding the chain'''
    this.rop_chain += b"A" * length
    this.rop_chain_text += f"rop_chain += b'A' * {length} # padding\n"

  def call(this, address):
    '''Direct Call to address'''
    this.rop_chain += this.decoding(address)

    if dword == this.decoding:
      tmp = "dword"
    else:
      tmp = "qword"
    this.rop_chain_text += f"rop_chain += {tmp}({address:#08x})\n"

  def set_regs(this, conditions):
    '''Tries to set registers'''

    for reg, value in conditions.items():
      # print(reg, value)
      flag = None

      # Finding a single pop gadget first
      for func in sorted(this.functions_for_rop):
        func_name = func[0].splitlines()[1]
        if re.match(fr".* pop_{reg}\(.*\):", func_name):
          addr = int(func[0].splitlines()[0].split()[0][3:-1], 16)
          this.rop_chain += this.decoding(addr)

          if isinstance(value, int):
            this.rop_chain += this.decoding(value)
          elif isinstance(value, str):
            this.rop_chain += value.encode('charmap')
          else:
            this.rop_chain += value

          tmp = func_name.split('def ')[1]
          tmp = tmp.split('(')[0]

          if isinstance(value, int):
            this.rop_chain_text += f"rop_chain += {tmp}({reg} = {value:#08x})\n"
          else:
            this.rop_chain_text += f"rop_chain += {tmp}({reg} = {value})\n"
          
          flag = 1
          break

      # XXX This will zero out other registers which might break the chain
      if not flag:
        for func in sorted(this.functions_for_rop):
          func_name = func[0].splitlines()[1]
          if re.match(fr".* pop_.*{reg}.*", func_name):
            params = func_name.split('(')[0].split('_')[1:]

            tmp = func_name.split('def ')[1]
            tmp = tmp.split('(')[0]

            this.rop_chain_text += f"rop_chain += {tmp}("
            for i in params:
              if reg == i:
                this.rop_chain += this.decoding(value)
                if isinstance(value, int):
                  this.rop_chain_text += f"{reg} = {value:#010x}"
                else:
                  this.rop_chain_text += f"{reg} = {value}"
              else:
                this.rop_chain += this.decoding(0)
            this.rop_chain_text += ")\n"
            flag = 1
            break

      if not flag:
        this.print_error(f"Failed in setting the condition {reg} = {value}")


  def clean(this):
    this.print_warning("Clearing out the chain")
    this.rop_chain = b""
    this.rop_chain_text = ""

  # XXX Implement
  def generate(this):
    return this.rop_chain

  def print_chain(this):
    return this.rop_chain_text
