#!/usr/bin/python3

import angr
import logging
import claripy
import pyvex
import os
from dataclasses import dataclass, field
from typing import List


"""
from patcherex.backends import ReassemblerBackend
from patcherex.patches import *
from patcherex.techniques import ShadowStack, ShiftStack, Adversarial, BinaryOptimization
from patcherex.techniques.binary_optimization import optimize_it
from patcherex.errors import BinaryOptimizationError
"""
from angrutils import *

logging.getLogger('angr.manager').setLevel(logging.DEBUG)

proj = angr.Project('bin/simple_test.bin', auto_load_libs=False, use_sim_procedures=True)
main = proj.loader.main_object.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.rebased_addr)

#state = proj.factory.full_init_state(remove_options=angr.options.simplification)
arg1 = claripy.BVS('arg1', 32)
state = proj.factory.full_init_state(args=["simple_test.bin", arg1])
simgr = proj.factory.simgr(state)
# Define the symbols we want to hook
symbols = ['printf']

class PrintfHook(angr.SimProcedure):
    def run(self, arg0, arg1):
        print("Got printf :" + str(arg0) + " " + str(arg1))
        #print(str(state.solver.eval(arg1)))

# Hook them all with the normal SimProc
for symbol in symbols:
    if symbol == "printf":
        proj.hook_symbol(symbol, PrintfHook())
    else:
        proj.hook_symbol(symbol,angr.SimProcedures['libc.so.6'][symbol])


def dbg_fn(state):
    print("State %s is about to do a function call" % state.inspect.function_address)

#state.inspect.b("call", action=dbg_fn)

# static analysises
#"""
# precise CFG
#cfg = proj.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=2)
# DDG requires that the CFG was init with keep_state=?True
cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state, keep_state=True)
plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  

# control dependance graph
#cdg = proj.analyses.CDG(cfg)

# data dependence graph
#ddg = proj.analyses.DDG(cfg)

target_func = cfg.kb.functions.function(name="printf")

target_node = cfg.get_any_node(target_func.addr)

#bs = proj.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

#print(bs)
#"""
#bs.debug_repr()
# symbolic execution
simgr.explore(find=0x401278)
#simgr.run()


#bo = proj.analyses.BinaryOptimizer(cfg, {'register_reallocation', 'redundant_stack_variable_removal', 'constant_propagation'})
func_kb = angr.KnowledgeBase(proj, None)

ddg = proj.analyses.DDG(kb=func_kb,cfg=cfg, call_depth=10)
#ddg = proj.analyses.DDG(kb=proj.kb,cfg=cfg)

fn = proj.kb.functions.get_by_addr(main.rebased_addr)

main = cfg.functions.function(name='main')
logging.getLogger('angr.analyses.vfg').setLevel(logging.DEBUG)

# remove alloca statements with pattern matching

"""
idea : if we delete the useless variables, IDA/Ghidra will be able to perform constant propagation.
* supprimer la paire d'instructions de la forme suivante:  tYY/tZZ = Add64(tXX,0xffffffffffffffXX), where tXX is the same for both statements.
* remplacer t124 = LDle:I32(tZZ) par la constante de l'instruction STle(tYY) = 0x024ced0a, à supprimer aussi. Ici, tyy vaut soit tYY, soit tZZ

26 | t119 = Add64(t105,0xffffffffffffffec)
27 | STle(t119) = 0x024ced0a #type(st) = pyvex.stmt.Store
30 | t121 = Add64(t105,0xffffffffffffffec)
31 | t124 = LDle:I32(t121) # type(st) = 

extract on the fly or save the IRStatement ?
"""
@dataclass
class PatternAlloca:
    load_destination:int = 0
    load_source:int = 0
    store_destination:int = 0
    store_value:pyvex.const.U32 = None
    stack_variables:list = None # kind of t119 = Add64(t105,0xffffffffffffffec)
    load_instruction:pyvex.stmt.WrTmp = None#pyvex.stmt.WrTmp
    store_instruction:pyvex.stmt.Store = None
    is_complete:bool = False

blk = next(main.blocks)

# returns an integer
def get_stack_index(ir_statement):
    
    if not isinstance(ir_statement, pyvex.stmt.WrTmp):
        raise Exception("Instruction should be of type pyvex.stmt.WrTmp")

    expr = list(ir_statement.expressions)

    return expr[0].child_expressions[0].tmp.real

# returns an integer
def get_stack_destination_index(ir_statement):
    
    if not isinstance(ir_statement, pyvex.stmt.WrTmp):
        raise Exception("Instruction should be of type pyvex.stmt.WrTmp")

    return ir_statement.tmp

# returns an integer
def get_store_destination_index(ir_statement):

    if not isinstance(ir_statement, pyvex.stmt.Store):
         raise Exception("Instruction should be of type pyvex.stmt.Store")

    expr = list(ir_statement.expressions)

    return expr[0].tmp.real

# returns an integer
# seemingly the same code as get_stack_index, but it's
# clearer that way and the API may change in the future.
def get_load_source_index(ir_statement):

    if not isinstance(ir_statement, pyvex.stmt.WrTmp):
         raise Exception("Instruction should be of type pyvex.stmt.Store")

    expr = list(ir_statement.expressions)

    return expr[0].child_expressions[0].tmp.real    

"""
26 | t119 = Add64(t105,0xffffffffffffffec)
27 | STle(t119) = 0x024ced0a #type(st) = pyvex.stmt.Store
"""
def is_relevant_store(pattern, ir_statement):

    if pattern.stack_variables is None:
        return False

    stack_variables = pattern.stack_variables
    
    store_destination = get_store_destination_index(ir_statement)

    for instr in stack_variables:
        load_source = get_stack_destination_index(instr) # check that

        if store_destination == load_source:
            return True

    return False

# 31 | t124 = LDle:I32(t121)
def is_relevant_load(pattern, ir_statement):

    stack_variables = pattern.stack_variables
    memory_offset = get_load_source_index(ir_statement)

    for instr in stack_variables:
        load_source = get_stack_index(instr)

        if memory_offset == load_source:
            return True

    return False    

"""
in short, delete every statement, but the load instruction becomes an assignment, where
the load destination is assigned the RH constantof the store instruction.
"""
def patch_ir(pattern):
    return None

def collect_relevant_instruction(current_pattern, ir_statement):
    
    if isinstance(ir_statement, pyvex.stmt.WrTmp):

        # distinguish between Load and Add64
        nb_expressions = len(list(ir_statement.expressions))

        if nb_expressions == 3:
            
            child = next(ir_statement.expressions)
            op = child.op
            
            if not op == "Iop_Add64":
                #print(f"Skipped expression with op = {op}")
                return current_pattern
            
            # found an Add64
            ir_statement.pp()
            if current_pattern.stack_variables is not None:
                current_pattern.stack_variables.append(ir_statement)
            else:
                current_pattern.stack_variables = [ir_statement]

        elif nb_expressions == 2:
            
            if is_relevant_load(current_pattern, ir_statement):
                current_pattern.load_instruction = ir_statement

            print("Found the end of the pattern")
            ir_statement.pp()
            current_pattern.is_complete = True

    # STle(t119) = 0x024ced0a
    elif isinstance(ir_statement, pyvex.stmt.Store):
        # check if destination is equal to one of the known stack variables.
        if is_relevant_store(current_pattern, ir_statement):
            current_pattern.store_destination = get_store_destination_index(ir_statement)
            current_pattern.store_instruction = ir_statement
            ir_statement.pp()
       
    return current_pattern

def remove_useless_alloca(blk):
    current_pattern = PatternAlloca()

    for ir_statement in blk.vex.statements:
        current_pattern = collect_relevant_instruction(current_pattern, ir_statement)

        if current_pattern.is_complete:
            print("DONE")
            break
        
    return current_pattern

current_pattern = remove_useless_alloca(blk)

# optimizations
"""filepath = "/home/vladimir/dev/llvm-pass/bin/simple_test.bin"
filename = "simple_test.bin"
target_filepath = os.path.join('/', 'tmp', 'optimized_binaries', os.path.basename(filename))
rr_filepath = target_filepath + ".rr"
cp_filepath = target_filepath + ".cp"

# register reallocation first
b1 = ReassemblerBackend(filepath, debugging=True)
cp = BinaryOptimization(filepath, b1, {'register_reallocation'})
#cp = BinaryOptimization(filepath, b1, {'redundant_stack_variable_removal'})
patches = cp.get_patches()
b1.apply_patches(patches)
r = b1.save(rr_filepath)

if not r:
    print("Compiler says:")
    print(b1._compiler_stdout)
    print(b1._compiler_stderr)

"""

"""
vfg = proj.analyses.VFG(cfg, \
                        start=main.addr, \
                        context_sensitivity_level=1, \
                        interfunction_level=3, \
                        record_function_final_states=True, \
                        max_iterations=80, \
                        )
"""
"""
ddg_vsa = proj.analyses.VSA_DDG(vfg, start_addr=main.addr, \
                        context_sensitivity_level=1, \
                        interfunction_level=3, \
                        keep_data=True)
"""

data_graph = ddg.graph
#data_graph = vfg.graph
"""
for n0 in data_graph.nodes():
    if not isinstance(n0.variable, SimConstantVariable):
        print(repr(n0) + " is not a Constant")
        continue

    n1s = list(data_graph.successors(n0))
    if len(n1s) != 1:
        print(repr(n1) + " has not one and only one successor.")
        continue
    n1 = n1s[0]

    if not isinstance(n1.variable, SimRegisterVariable):
        print(repr(n1.variable) + " is not a ConSimRegisterVariable")
        continue

    if len(list(data_graph.predecessors(n1))) != 1:
        print(repr(len(list(data_graph.predecessors(n1)))) + " ;len(list(data_graph.predecessors(n1))) is not 1")
        continue

    n2s = list(data_graph.successors(n1))
    if len(n2s) != 1:
        print(repr(len(n2s)) + " is not a 1 (len(n2s))")        
        continue
    n2 = n2s[0]

    if not isinstance(n2.variable, SimMemoryVariable):
        print(repr(n2.variable) + ", n2.variable is not a SimMemoryVariable")        
        continue

    n2_inedges = data_graph.in_edges(n2, data=True)
    if len([ 0 for _, _, data in n2_inedges if 'type' in data and data['type'] == 'mem_data' ]) != 1:
        print("hmmm....wtf :F")
        continue

    #cp = ConstantPropagation(n0.variable.value, n0.location, n2.location)
    #self.constant_propagations.append(cp)
    print("Found a propagable constant!")

#vc = proj.analyses.VariableRecovery(fn, 10)
"""