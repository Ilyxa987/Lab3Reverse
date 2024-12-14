import angr
import monkeyhex
from triton import *
from angrutils import *
import lief
import claripy
from StaticTableImports import *

length = 0
buf_addr = 0

sink_addr = list()

def hook_gets(state: angr.SimState):
    global length
    global buf_addr
    length = state.regs.rdx
    buf_addr = state.regs.rcx
    length = claripy.backends.concrete.convert(length).value
    buf_addr = claripy.backends.concrete.convert(buf_addr).value

def readfile_hook(state: angr.SimState):
    global length
    global buf_addr
    buf_addr = state.regs.rdx
    length = state.regs.r8d
    length = claripy.backends.concrete.convert(length).value
    buf_addr = claripy.backends.concrete.convert(buf_addr).value

def hook_reg_open_key_exw(state : angr.SimState):
    hKey = state.solver.eval(state.regs.rcx)  # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)  # Второй аргумент (LPCWSTR)
    ulOptions = state.solver.eval(state.regs.r8)  # Третий аргумент (DWORD)
    samDesired = state.solver.eval(state.regs.r9)  # Четвертый аргумент (REGSAM)

    # Фиктивный дескриптор ключа (возвращаемое значение в phkResult)
    phkResult_ptr = state.mem[state.regs.rbp + 0x10].int.resolved

    # Логирование
    print(f"Hooked RegOpenKeyExW: "
          f"hKey={hKey}, lpSubKey_ptr={lpSubKey_ptr}, ulOptions={ulOptions}, samDesired={samDesired}")

    # Установка фиктивного значения для phkResult (например, дескриптор 0x1234)
    state.memory.store(phkResult_ptr, claripy.BVV(0x1234, 64))  # 64-битный дескриптор

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)


import sys

sources = {'gets_s': [hook_gets, 6], 'ReadFile' : [readfile_hook, 6], 'RegOpenKeyExW' : [hook_reg_open_key_exw, 6]}

sink = ['puts', 'WriteFile']

filename = input("Введите название файла:\n")

""" Загрузка файла """
proj = angr.Project(filename, load_options={'auto_load_libs': False})

lib = [hex(x.rebased_addr) for x in proj.loader.main_object.imports.values()]  # Загрузка таблицы импортов
print(lib)
""""""

""" Статическая загрузка всех адресов, где вызываются импортные функции """
call_imports = GetStaticImportAdderess(proj)
address_names = dict()

for key, value in call_imports.items():
    index = lib.index(hex(int(value, 0)))
    print(f"  0x{key:x} in lib", list(proj.loader.main_object.imports.keys())[index])
    address_names.update({key: list(proj.loader.main_object.imports.keys())[index]})
    if list(proj.loader.main_object.imports.keys())[index] in sources.keys():
        proj.hook(key, sources[list(proj.loader.main_object.imports.keys())[index]][0],
                  sources[list(proj.loader.main_object.imports.keys())[index]][1])
    elif list(proj.loader.main_object.imports.keys())[index] in sink:
        if list(proj.loader.main_object.imports.keys())[index] == 'puts':
            addrs = find_put_args(key, proj)
            for i in range(len(addrs)):
                sink_addr.append(addrs[i])
        else:
            sink_addr.append(key)

""""""

print(call_imports)
print(address_names)
print(sink_addr)

initial_state = proj.factory.call_state(0x140001000)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
simulation = proj.factory.simgr(initial_state)

for i in range(len(sink_addr)):
    symb_vector = claripy.BVS('input', length * 8)
    initial_state.memory.store(buf_addr, symb_vector)

    simulation = proj.factory.simgr(initial_state)

    simulation.explore(find=sink_addr[i])

    if simulation.found:
        solution_state = simulation.found[0]
        win_sequence = ''
        finishedTracing = False
        for win_block in solution_state.history.bbl_addrs.hardcopy:
            win_block = proj.factory.block(win_block)
            addresses = win_block.instruction_addrs
            for address in addresses:
                win_sequence += 't:' + hex(address) + '\n'
                if address == sink_addr[i]:
                    finishedTracing = True
                    break
            if finishedTracing:
                break
        win_sequence = win_sequence[:-1]
        print(win_sequence)
        print(hex(sink_addr[i]), solution_state.solver.eval(symb_vector, cast_to=bytes))
    else:
        print('Could not find the solution')

