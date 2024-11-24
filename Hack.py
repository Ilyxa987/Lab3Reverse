from Hooks import *
from StaticFind import *

filename = "test3.exe"

""" Загрузка файла """
proj = angr.Project(filename, load_options={'auto_load_libs': False})

lib = [hex(x.rebased_addr) for x in proj.loader.main_object.imports.values()]  # Загрузка таблицы импортов
# print(lib)
""""""

""" Статическая загрузка всех адресов, где вызываются импортные функции """
call_imports = GetStaticImportAddress(proj)
import_funcs = []
for key, value in call_imports.items():
    index = lib.index(hex(int(value, 0)))
    """ Где вызывается - кого вызывает - куда идет """
    import_funcs.append([key, list(proj.loader.main_object.imports.keys())[index], value])
    # print(f"  0x{key:x} in lib", list(proj.loader.main_object.imports.keys())[index], hex(int(value, 0)))

for i in import_funcs:
    print(f"0x{i[0]:x}", i[1], hex(int(i[2], 0)))
""""""


clear_encode()

initial_state = proj.factory.call_state(0x140001000)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

symb_vector = claripy.BVS('input', 256 * 8)
initial_state.memory.store(0x7FFFFFFFFFEFEC0, symb_vector)

proj.hook(int("0x14000103a", 0), hook_reg_open_key_exw, 6)
proj.hook(int("0x14000106f", 0), hook_reg_query_value_exw, 6)
proj.hook(int("0x1400010af", 0), hook_reg_get_value_w, 6)
proj.hook(int("0x1400010ef", 0), hook_reg_set_value_exw, 6)

simulation = proj.factory.simgr(initial_state)

simulation.explore(find=0x140001100)

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
                finishedTracing = True
                break
        if finishedTracing:
            break
    win_sequence = win_sequence[:-1]
    print(solution_state.solver.eval(symb_vector, cast_to=bytes))
else:
    print('Could not find the solution')

print(encoded)
