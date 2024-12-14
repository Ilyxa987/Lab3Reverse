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

    global filename
    namekey = ''
    binary = lief.parse(filename)
    flag = 0
    for i in binary.get_content_from_virtual_address(lpSubKey_ptr, 100):
        if i == 0:
            if flag == 0:
                flag = 1
            else:
                break
        else:
            flag = 0
            namekey += chr(i)
            #print(chr(i), end='')
    #print()

    print(f"Hooked RegOpenKeyExW: "
          f"hKey={hKey}, lpSubKey_ptr={namekey}, ulOptions={ulOptions}, samDesired={samDesired}")

    # Установка фиктивного значения для phkResult (например, дескриптор 0x1234)
    state.memory.store(phkResult_ptr, claripy.BVV(0x1234, 64))  # 64-битный дескриптор

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)

def hook_reg_query_value_exw(state):
    hKey = state.solver.eval(state.regs.rcx)  # Первый аргумент (HKEY)
    lpValueName_ptr = state.solver.eval(state.regs.rdx)  # Второй аргумент (LPCWSTR)
    lpReserved = state.solver.eval(state.regs.r8)  # Третий аргумент
    lpType_ptr = state.solver.eval(state.regs.r9)  # Четвертый аргумент

    # Имитация данных о результатах запроса реестра
    lpData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x30, 8))

    global filename
    namekey = ''
    binary = lief.parse(filename)
    flag = 0
    for i in binary.get_content_from_virtual_address(lpValueName_ptr, 100):
        if i == 0:
            if flag == 0:
                flag = 1
            else:
                break
        else:
            flag = 0
            namekey += chr(i)

    # Логирование
    print(f"Hooked RegQueryValueExW: "
          f"hKey={hex(hKey)}, lpValueName_ptr={namekey}")

    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)

def hook_reg_get_value_w(state):
    hKey = state.solver.eval(state.regs.rcx)  # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)  # Второй аргумент (LPCWSTR)
    lpValue_ptr = state.solver.eval(state.regs.r8)  # Третий аргумент
    dwFlags = state.solver.eval(state.regs.r9)  # Четвертый аргумент (флаги)

    lpData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x40, 8))
    # print(hex(lpData_ptr), hex(pcbData_ptr))

    global filename
    namekey = ''
    binary = lief.parse(filename)
    flag = 0
    for i in binary.get_content_from_virtual_address(lpValue_ptr, 100):
        if i == 0:
            if flag == 0:
                flag = 1
            else:
                break
        else:
            flag = 0
            namekey += chr(i)

    # Логирование
    print(f"Hooked RegGetValueW: "
          f"hKey={hex(hKey)}, lpSubKey_ptr={hex(lpSubKey_ptr)}, lpValue_ptr={namekey}, dwFlags={dwFlags}")

    global buf_addr
    global length

    length = 64
    buf_addr = claripy.backends.concrete.convert(state.mem[state.regs.rsp + 0x28].uint64_t.resolved).value

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 32)  # Возвращает 0 (успех)

def hook_reg_set_value_exw(state):
    hKey = state.solver.eval(state.regs.rcx)  # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)  # Второй аргумент (LPCWSTR)
    lpValue_ptr = state.solver.eval(state.regs.r8)  # Третий аргумент
    dwFlags = state.solver.eval(state.regs.r9)  # Четвертый аргумент (флаги)

    # Извлечь дополнительные аргументы из стека
    pdwType_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))  # Указатель на тип (REG_*)
    pvData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x30, 8))  # Указатель на буфер данных
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x38, 8))  # Указатель на размер данных

    global filename
    namekey = ''
    binary = lief.parse(filename)
    flag = 0
    for i in binary.get_content_from_virtual_address(lpSubKey_ptr, 100):
        if i == 0:
            if flag == 0:
                flag = 1
            else:
                break
        else:
            flag = 0
            namekey += chr(i)

    # Логирование
    print(
        f"Hooked RegSetValueW: "
        f"hKey={hex(hKey)}, lpSubKey_ptr={namekey}, lpValue_ptr={hex(lpValue_ptr)}, "
        f"{dwFlags, pdwType_ptr, hex(pvData_ptr), hex(pcbData_ptr)}")

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 32)  # Возвращает 0 (успех)
import sys

sources = {'gets_s': [hook_gets, 6], 'ReadFile' : [readfile_hook, 6], 'RegOpenKeyExW' : [hook_reg_open_key_exw, 6], \
            'RegQueryValueExW': [hook_reg_query_value_exw, 6], 'RegGetValueW' : [hook_reg_get_value_w, 6], \
           'RegSetValueExW': [hook_reg_set_value_exw, 6]}

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

initial_state = proj.factory.call_state(0x140001000)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
simulation = proj.factory.simgr(initial_state)

#buf_addr = 0x7FFFFFFFFFEFEc0
#length = 256
simulation.run()

print('Simvectors ready!\n')

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
        #print(win_sequence)
        if buf_addr != 0:
            print(hex(sink_addr[i]), solution_state.solver.eval(symb_vector, cast_to=bytes))
    else:
        print(hex(sink_addr[i]), 'Could not find the solution or solution in func arguments')
    print()
