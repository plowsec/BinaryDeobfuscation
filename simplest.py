from __future__ import print_function
from pdb import pm

from future.utils import viewitems

from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm
from miasm.expression.expression import *
from miasm.core import asmblock
from miasm.arch.x86.ira import ir_a_x86_32
from miasm.analysis.data_flow import dead_simp

from miasm.analysis.cst_propag import add_state, propagate_cst_expr
from miasm.expression.simplifications import expr_simp

# First, asm code
asmcfg, loc_db = parse_asm.parse_txt(mn_x86, 32, '''
main:
    PUSH       EBP
    MOV        EBP, ESP
    SUB        ESP, 0x40
    MOV ECX, 0x51CEB16D
    MOV        DWORD PTR [EBP+0xf8], ECX
    MOV        ECX, DWORD PTR [EBP+0xf8]
    MOV        EDX, 0x51CEB454
    XOR        ECX, EDX
    MOV        EAX, ECX
    RET
''')


loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
for block in asmcfg.blocks:
    print(block)


print("symbols:")
print(loc_db)
patches = asmblock.asm_resolve_final(mn_x86, asmcfg, loc_db)

# Translate to IR
ir_arch = ir_a_x86_32(loc_db)
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

# Display IR
for lbl, irblock in viewitems(ircfg.blocks):
    print(irblock)

# Dead propagation
open('graph.dot', 'w').write(ircfg.dot())
print('*' * 80)
init_infos = ir_arch.arch.regs.regs_init
propagate_cst_expr(ir_arch, ircfg, 0, init_infos)
ircfg.simplify(expr_simp)
dead_simp(ir_arch, ircfg)
open('graph2.dot', 'w').write(ircfg.dot())

# Display new IR
print('new ir blocks')
for lbl, irblock in viewitems(ircfg.blocks):
    print(irblock)

