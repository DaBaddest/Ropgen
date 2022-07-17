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
