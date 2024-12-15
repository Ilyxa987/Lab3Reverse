import angr
import monkeyhex
from triton import *
from angrutils import *
import lief
import claripy
from StaticTableImports import *

length = []
buf_addr = []

hook_addr = []

sink_addr = list()

def hook_gets(state: angr.SimState):
    global length
    global buf_addr
    size = state.regs.rdx
    buffer = state.regs.rcx
    if claripy.backends.concrete.convert(buffer).value not in buf_addr:
        length.append(claripy.backends.concrete.convert(size).value)
        buf_addr.append(claripy.backends.concrete.convert(buffer).value)
    #print(hex(buf_addr), hex(state.addr))

def readfile_hook(state: angr.SimState):
    global length
    global buf_addr
    buffer = state.regs.rdx
    size = state.regs.r8d
    if claripy.backends.concrete.convert(buffer).value not in buf_addr:
        length.append(claripy.backends.concrete.convert(size).value)
        buf_addr.append(claripy.backends.concrete.convert(buffer).value)

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

    if claripy.backends.concrete.convert(state.mem[state.regs.rsp + 0x28].uint64_t.resolved).value not in buf_addr:
        length.append(64)
        buf_addr.append(claripy.backends.concrete.convert(state.mem[state.regs.rsp + 0x28].uint64_t.resolved).value)

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 32)  # Возвращает 0 (успех)

def hook_reg_set_value_exw(state : angr.SimState):
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

def strcpy_hook(state: angr.SimState):
    dest = state.regs.rcx
    sour = state.regs.r8
    state.regs.rcx = sour
    print(sour, state.regs.rcx)
    print('strcpy')


def hook_getmodulefilenameW(state: angr.SimState):
    name = state.regs.rdx
    size = state.regs.r8
    global length
    global buf_addr
    if claripy.backends.concrete.convert(name).value not in buf_addr:
        length.append(claripy.backends.concrete.convert(size).value)
        buf_addr.append(claripy.backends.concrete.convert(name).value)


def hook_memchr(state: angr.SimState):
    buffer = state.solver.eval(state.regs.rcx)
    symb = state.solver.eval(state.regs.edx)
    size = state.solver.eval(state.regs.r8)
    print(
        f"Hooked memchr: "
        f"buf={hex(buffer)}, char={chr(symb)}, size={size}")
    for i in range(size):
        if symb == state.solver.eval(state.mem[buffer + i * 8].uint8_t.resolved):
            state.regs.rax = claripy.BVV(1, 64)
            return
    state.regs.rax = claripy.BVV(0, 64)
    state.regs.pc = state.mem[state.regs.rsp].uint64_t.resolved
    #state.move(state.solver.eval(state.regs.rsp))


def hook_writefile(state:angr.SimState):
    print('write')

import sys

sources = {'gets_s': [hook_gets, 6], 'ReadFile' : [readfile_hook, 6], 'RegOpenKeyExW' : [hook_reg_open_key_exw, 6], \
            'RegQueryValueExW': [hook_reg_query_value_exw, 6], 'RegGetValueW' : [hook_reg_get_value_w, 6], \
           'RegSetValueExW': [hook_reg_set_value_exw, 6], 'GetModuleFileNameW' : [hook_getmodulefilenameW, 6], \
           'fgets': [hook_gets, 6]}

sink = ['puts', 'WriteFile', 'RegSetValueExW', 'SetPriorityClass', 'FindFirstFileW', 'CloseHandle']

hooks = {'strcpy_s': [strcpy_hook, 6], 'WriteFile': [hook_writefile, 6], 'memchr' : [hook_memchr, 6]}

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
        hook_addr.append(key)
        proj.hook(key, sources[list(proj.loader.main_object.imports.keys())[index]][0],
                  sources[list(proj.loader.main_object.imports.keys())[index]][1])
    if list(proj.loader.main_object.imports.keys())[index] in sink:
        if list(proj.loader.main_object.imports.keys())[index] == 'puts':
            addrs = find_put_args(key, proj)
            for i in range(len(addrs)):
                sink_addr.append(addrs[i])
        else:
            sink_addr.append(key)
    if list(proj.loader.main_object.imports.keys())[index] in hooks.keys():
        hook_addr.append(key)
        proj.hook(key, hooks[list(proj.loader.main_object.imports.keys())[index]][0],
                  hooks[list(proj.loader.main_object.imports.keys())[index]][1])

""""""

print(call_imports)
print(address_names)

#proj.hook(0x14000108f, hook_memchr)

initial_state = proj.factory.call_state(0x140001000)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
simulation = proj.factory.simgr(initial_state)

simulation.run()

print('Simvectors ready!\n')

# buf_addr = 0x7fffffffffefda0
# length = 260
for i in range(len(sink_addr)):
    for j in range(len(buf_addr)):
        symb_vector = claripy.BVS('input', length[j] * 8)
        initial_state.memory.store(buf_addr[j], symb_vector)

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
