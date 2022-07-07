supported_archs = {
  b"x86-64"  : "x64",
  b"80386"   : "x86",
  b"arm"     : "arm",
  b"aarch64" : "aarch64"
}


# Patterns used for selecting gadgets which might be more useful than others
patterns_x86 = [r"^(pop e..; )*ret"
                r"^(pop e..; )call e..",
                r"^(pop e..; )jmp e..",
                r"^mov dword ptr \[e..\], e..; ret",
               ]

patterns_x64 = [r"^(pop e..; )*ret",
                r"^(pop r..; )*ret",
                r"^mov [dq]word ptr \[r..\], r..; ret",
                r"^mov [dq]word ptr \[r..\], e..; ret",
               ]

patterns_arm = [r"^pop {(...?, )+pc}",
                r"^bl?x? ...?$",
                r"^str.*? r..?, \[r..?\]",
               ]

patterns_aarch64 = None


# List of registers
reg_map_x64 = {
  "rax": None,
  "rbx": None,
  "rcx": None,
  "rdx": None,
  "rdi": None,
  "rsi": None,
  "rsp": None,
  "rbp": None,
  "r8" : None,
  "r9" : None,
  "r10": None,
  "r11": None,
  "r12": None,
  "r13": None,
  "r14": None,
  "r15": None,
}

reg_map_x86 = {
  "eax": None,
  "ebx": None,
  "ecx": None,
  "edx": None,
  "edi": None,
  "esi": None,
  "esp": None,
  "ebp": None,
}

reg_map_arm = {
  "r0" : None,
  "r1" : None,
  "r2" : None,
  "r3" : None,
  "r4" : None,
  "r5" : None,
  "r6" : None,
  "r7" : None,
  "r8" : None,
  "r9" : None,
  "r10": None,
  "r11": None,
  "r12": None,
  "r13": None,
  "r14": None,
  "r15": None,
  "sp" : None,
  "lr" : None,
}

reg_map_aarch64 = {
}
