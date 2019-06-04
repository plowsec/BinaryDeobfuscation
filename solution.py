#!/usr/bin/python2

from miasm.arch.x86.arch import mn_x86
from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.core.bin_stream import bin_stream_str
from miasm.arch.x86.disasm import dis_x86_32
from miasm.arch.x86.ira import ir_a_x86_64
from miasm.arch.x86.regs import all_regs_ids, all_regs_ids_init
# from miasm.ir.symbexec import symbexec
from miasm.analysis.cst_propag import add_state, propagate_cst_expr
from miasm.expression.simplifications import expr_simp
from miasm.analysis.data_flow import dead_simp, \
    merge_blocks, remove_empty_assignblks

mn = Machine('x86_64')

# Create an intermediate representation object
loc_db = LocationDB()
ira = mn.ira(loc_db)

# create an empty ircfg
ircfg = ira.new_ircfg()


# Binary path and offset of the target function
offset = 0x1150
fname = "bin/simple_test.bin"

# Get Miasm's binary stream
bin_file = open(fname).read()
bin_stream = bin_stream_str(bin_file)

# Disassemble blocks of the function at 'offset'
mdis = mn.dis_engine(bin_stream)
disasm = mdis.dis_multiblock(offset)

ircfg = ira.new_ircfg_from_asmcfg(disasm)
entry_points = set([mdis.loc_db.get_offset_location(offset)])

# Create target IR object and add all basic blocks to it
ir = ir_a_x86_64(mdis.symbol_pool)
for bbl in disasm.blocks:
    print(bbl.to_string(disasm.loc_db))
    ira.add_asmblock_to_ircfg(bbl, ircfg)

init_infos = ira.arch.regs.regs_init
propagate_cst_expr(ira, ircfg, offset, init_infos)
ircfg.simplify(expr_simp)

modified = True
iteration = 0
while modified:
    print("Applying simplification pass " + str(iteration))
    modified = False
    modified |= dead_simp(ira, ircfg)
    modified |= remove_empty_assignblks(ircfg)
    modified |= merge_blocks(ircfg, entry_points)
    iteration += 1

for lbl, irblock in ircfg.blocks.items():
    print(irblock.to_string(loc_db))


open("%s.propag.dot" % "bin/simplified.bin", 'w').write(ircfg.dot())
