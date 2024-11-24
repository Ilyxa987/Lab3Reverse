import winreg
from winreg import HKEY_LOCAL_MACHINE

import angr
import claripy
from StaticFind import *
from Hooks import *
import pefile
import angr.calling_conventions as cc

filename = "test3.exe"

""" Загрузка файла """
proj = angr.Project(filename, load_options={'auto_load_libs': False})

lib = [hex(x.rebased_addr) for x in proj.loader.main_object.imports.values()]  # Загрузка таблицы импортов
print(lib)
""""""

""" Статическая загрузка всех адресов, где вызываются импортные функции """
call_imports = GetStaticImportAddress(proj)

for key, value in call_imports.items():
    index = lib.index(hex(int(value, 0)))
    """где вызывается - кого вызывает - куда идет """
    print(f"  0x{key:x} in lib", list(proj.loader.main_object.imports.keys())[index], hex(int(value, 0)))
""""""

print(call_imports)

args = 0  # getaddrsource(proj,5368713274)
print(args)

# Указываем адрес функции
function_addr = 5368713274  # Замените на адрес функции


initial_state = proj.factory.call_state(0x140001000)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

symb_vector = claripy.BVS('input', 256 * 8)
initial_state.memory.store(0x7FFFFFFFFFEFEC0, symb_vector)

proj.hook(int("0x14000103a", 0), hook_reg_open_key_exw, 6)
proj.hook(int("0x14000106f", 0), hook_reg_query_value_exw, 6)
proj.hook(int("0x1400010af", 0), hook_reg_get_value_w, 6)
proj.hook(int("0x1400010ef", 0), hook_reg_set_value_exw, 6)

#proj.hook(int("0x1400010B9", 0),hook_140001126,2)
simulation = proj.factory.simgr(initial_state)

simulation.explore(find=0x140001100)

# If found a way to reach the address
if simulation.found:
    solution_state = simulation.found[0]
    win_sequence = ''
    finishedTracing = False
    for win_block in solution_state.history.bbl_addrs.hardcopy:
        win_block = proj.factory.block(win_block)
        addresses = win_block.instruction_addrs
        for address in addresses:
            win_sequence += 't:' + hex(address) + '\n'
            if address == 0x140001100:
                # Prevent sending the rest of the block addresses that aren't desired
                finishedTracing = True
                break
        if finishedTracing:
            break
    win_sequence = win_sequence[:-1]
    # print(win_sequence)
    # Print the string that Angr wrote to stdin to follow solution_state
    # print(solution_state.posix.dumps(1))
    print(solution_state.solver.eval(symb_vector, cast_to=bytes))
    # print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    print('Could not find the solution')
