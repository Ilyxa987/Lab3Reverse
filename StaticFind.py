import angr, claripy
from angr import *
import lief
import sys

from numpy import size
from sympy.codegen.cnodes import sizeof

def encode(lpSubKey_ptr, filename):
    flag = 0
    binary = lief.parse(filename)

    for i in binary.get_content_from_virtual_address(int(lpSubKey_ptr), 100):
        if i != 0:
            flag = 0
            print(chr(i), end='')
        if i == 0:
            flag += 1
        if flag == 2:
            break
    print()

# Определяем функцию-хук для RegOpenKeyExW
def hook_reg_open_key_exw(state):


    hKey = state.solver.eval(state.regs.rcx)  # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)  # Второй аргумент (LPCWSTR)
    ulOptions = state.solver.eval(state.regs.r8)  # Третий аргумент (DWORD)
    samDesired = state.solver.eval(state.regs.r9)  # Четвертый аргумент (REGSAM)

    # Фиктивный дескриптор ключа (возвращаемое значение в phkResult)
    phkResult_ptr = state.mem[state.regs.rbp + 0x10].int.resolved

    encode(lpSubKey_ptr, "test3.exe")

    # Логирование аргументов (для отладки)
    print(f"Hooked RegOpenKeyExW: hKey={hKey}, lpSubKey_ptr={lpSubKey_ptr}, ulOptions={ulOptions}, samDesired={samDesired}")

    # Установка фиктивного значения для phkResult (например, дескриптор 0x1234)
    state.memory.store(phkResult_ptr, claripy.BVV(0x1234, 64))  # 64-битный дескриптор

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)


import claripy
def hook_reg_query_value_exw(state):
        # Extract arguments
        hKey = state.solver.eval(state.regs.rcx)
        lpValueName_ptr = state.solver.eval(state.regs.rdx)
        lpReserved = state.solver.eval(state.regs.r8)
        lpType_ptr = state.solver.eval(state.regs.r9)

        # Simulate registry query result data
        lpData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))
        pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x30, 8))

        # Logging (for debugging)
        print(f"Hooked RegQueryValueExW: hKey={hex(hKey)}, lpValueName_ptr={hex(lpValueName_ptr)}")

        # Simulate setting the type (e.g., REG_SZ = 1)
        state.memory.store(lpType_ptr, claripy.BVV(1, 32))

        # Write sample data ("TestValue" in WCHAR)
        test_value = "TestValue".encode('utf-16le')  # Convert to UTF-16 for Windows registry strings
        for i, b in enumerate(test_value):
            state.memory.store(lpData_ptr + i, claripy.BVV(b, 8))  # Write each byte

        # Set the size of the returned data
        state.memory.store(pcbData_ptr, claripy.BVV(len(test_value), 32))

        # Set return value to ERROR_SUCCESS (0)
        state.regs.rax = claripy.BVV(0, 64)



"""
    # Извлекаем аргументы
    hKey = state.solver.eval(state.regs.rcx)            # Первый аргумент (HKEY)
    lpValueName_ptr = state.solver.eval(state.regs.rdx)  # Второй аргумент (LPCWSTR)
    lpReserved = state.solver.eval(state.regs.r8)       # Третий аргумент (LPDWORD)
    lpType = state.solver.eval(state.regs.r9)           # Четвертый аргумент (LPDWORD)
    lpData_ptr = state.solver.eval(state.regs.r10)      # Пятый аргумент (LPBYTE)
    lpcbData = state.solver.eval(state.regs.r11)        # Шестой аргумент (LPDWORD)

    # Логируем аргументы для отладки
    print(f"RegQueryValueExW called with hKey={hKey}, lpValueName_ptr={lpValueName_ptr}, "
          f"lpReserved={lpReserved}, lpType={lpType}, lpData_ptr={lpData_ptr}, lpcbData={lpcbData}")

    # Эмулируем возвращаемое значение для lpData (например, строка "FakeValue")
    fake_data = claripy.BVV(0x21, 32)  # Строка "FakeValue", которая будет записана в lpData

    # Записываем данные в память по адресу lpData
    state.memory.store(lpData_ptr, fake_data)

    # Эмулируем успешный возврат (ERROR_SUCCESS)
    state.regs.rax = claripy.BVV(0, 32)  # Возвращаем 0 для успешного завершения

    # Эмулируем тип данных (например, REG_SZ = 1 для строки)
    state.memory.store(lpType, claripy.BVV(1, 32))  # Тип данных (строка)

    # Эмулируем размер данных
    state.memory.store(lpcbData, claripy.BVV(0, 32))  # Размер данных

    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)
    print(9)"""


def hook_reg_get_value_w(state):
        # Extract arguments based on x64 calling convention (Windows):
        hKey = state.solver.eval(state.regs.rcx)  # First argument (handle to the open registry key)
        lpSubKey_ptr = state.solver.eval(state.regs.rdx)  # Second argument (pointer to subkey name)
        lpValue_ptr = state.solver.eval(state.regs.r8)  # Third argument (pointer to value name)
        dwFlags = state.solver.eval(state.regs.r9)  # Fourth argument (flags)


        encode(lpValue_ptr, "test3.exe")

        lpData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))
        pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x40, 8))
        print(hex(lpData_ptr), hex(pcbData_ptr))
        # Logging (optional, for debugging)
        print(
            f"Hooked RegGetValueW: hKey={hex(hKey)}, lpSubKey_ptr={hex(lpSubKey_ptr)}, lpValue_ptr={hex(lpValue_ptr)}, dwFlags={dwFlags}")

        # Return ERROR_SUCCESS (0) in RAX
        state.regs.rax = claripy.BVV(0, 32)  # ERROR_SUCCESS
def hook_reg_set_value_exw(state):
    # Extract arguments based on Windows x64 calling convention:
    hKey = state.solver.eval(state.regs.rcx)  # Handle to the open registry key
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)  # Pointer to subkey (could be NULL)
    lpValue_ptr = state.solver.eval(state.regs.r8)  # Pointer to value name
    dwFlags = state.solver.eval(state.regs.r9)  # Flags (typically 0)

    encode(lpSubKey_ptr, "test3.exe")

    # Extract additional arguments from the stack:
    pdwType_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))  # Pointer to type (REG_*)
    pvData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x30, 8)) # Pointer to data buffer
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x38, 8))  # Pointer to data size

    # Logging (for debugging purposes)
    print(f"Hooked RegSetValueW: hKey={hex(hKey)}, lpSubKey_ptr={hex(lpSubKey_ptr)}, lpValue_ptr={hex(lpValue_ptr)}, {dwFlags,pdwType_ptr,hex(pvData_ptr),hex(pcbData_ptr)}")

    # Simulate returning the type (e.g., REG_SZ = 1 for string data)
 #   state.memory.store(pdwType_ptr, claripy.BVV(1, 32))  # Assume REG_SZ type (string)

    # Simulate returning some mock data (for example, "TestValue" in WCHAR/UTF-16)
    test_data = "TestValue".encode('utf-16le')
    for i, byte in enumerate(test_data):
        state.memory.store(pvData_ptr + i, claripy.BVV(byte, 8))  # Write each byte of the string

    # Set the data size (number of bytes written)
    state.memory.store(pcbData_ptr, claripy.BVV(len(test_data), 32))

    # Return ERROR_SUCCESS (0) in RAX to indicate success
    state.regs.rax = claripy.BVV(0, 32)  # Return value: ERROR_SUCCESS (0)

def hook_140001126(state):
    print(state.regs.rsp)
    print(9999)

def GetStaticImportAdderess(p : angr.Project):
    lib = [hex(x.rebased_addr) for x in p.loader.main_object.imports.values()]
    call_addresses = {}
    cfg = p.analyses.CFGFast()
    cfg.normalize()
    for func_node in cfg.kb.functions.values():
        for block in func_node.blocks:
            addr = block.addr - 1 if block.thumb else block.addr
            ins_addr = list(block._project.analyses.Disassembly(ranges=[(addr, addr + block.size)], thumb=block.thumb,
                                                                block_bytes=block.bytes).raw_result_map["instructions"])
            if len(ins_addr) > 0:
                ins_addr = ins_addr[-1]
                a = str(list(block._project.analyses.Disassembly(ranges=[(addr, addr + block.size)], thumb=block.thumb,
                                                                 block_bytes=block.bytes).raw_result_map[
                                 "instructions"].values())[-1].render())
                for i in lib:
                    if i in a:
                        call_addresses.__setitem__(ins_addr, i)
                        break
    return call_addresses

def SearchFunc(p: angr.Project, funcaddr: str):
    cfg = p.analyses.CFGFast()
    cfg.normalize()
    arguments = list()
    argument = None
    for func_node in cfg.kb.functions.values():
        for block in func_node.blocks:
            #block.pp()
            addr = block.addr - 1 if block.thumb else block.addr
            ins_addr = list(block._project.analyses.Disassembly(ranges=[(addr, addr + block.size)], thumb=block.thumb,
                                                                block_bytes=block.bytes).raw_result_map["instructions"])
            for i in range(len(ins_addr)):
                a = str(list(block._project.analyses.Disassembly(ranges=[(addr, addr + block.size)],
                                                                 thumb=block.thumb,
                                                                 block_bytes=block.bytes).raw_result_map["instructions"].values())[i].render())
                if 'push' in a:
                    argument = a
                if funcaddr in a:
                    print(hex(list(block._project.analyses.Disassembly(ranges=[(addr, addr + block.size)],
                                                                 thumb=block.thumb,
                                                                 block_bytes=block.bytes).raw_result_map["instructions"].keys())[i]))
                    arguments.append(argument.split(' ')[4].split("'")[0])
                    break
    return arguments

 # for key, value in call_addresses.items():
    #     index = lib.index(hex(int(value, 0)))
    #     print(f"  0x{key:x} in lib", list(proj.loader.main_object.imports.keys())[index])

def FindArgs(funcname:str, call_addresses:dict, proj:angr.Project):
    lib = proj.loader.main_object.imports
    addr = lib[funcname]
    cfg = proj.analyses.CFGFast()
    cfg.normalize()
    arguments = list()
    #binary = lief.parse("test1.exe")
    for key, value in call_addresses.items():
        if value == hex(addr.rebased_addr):
            for func_node in cfg.functions.values():
                #print(hex(func_node.addr), hex(func_node.addr + func_node.size))
                if ('print' in funcname or 'scanf' in funcname) and key > func_node.addr and key < func_node.addr + func_node.size:
                    print(hex(func_node.addr))
                    arguments = SearchFunc(proj, func_node.name)
                    # for block in func_node.blocks:
                    #     insns = block._project.analyses.Disassembly(ranges=[(block.addr, block.addr + block.size)],
                    #                                                 thumb=block.thumb,
                    #                                                 block_bytes=block.bytes).raw_result_map["instructions"]
                    #     for i in range(len(insns.values()) - 1, -1, -1):
                    #         #print(str(list(insns.values())[i].render()))
                    #         if 'esi' in str(list(insns.values())[i].render()) and 'mov' in str(list(insns.values())[i].render()):
                    #             arguments.append(str(list(insns.values())[i].render()).split('[')[2].split(']')[0])
                else:
                    for block in func_node.blocks:
                        if key >= block.addr and key <= block.addr + block.size:
                            insns = block._project.analyses.Disassembly(ranges=[(block.addr, block.addr + block.size)], thumb=block.thumb,block_bytes=block.bytes).raw_result_map["instructions"]
                            for i in range(len(insns.values())-1, -1, -1):
                                if (funcname == 'puts' or funcname == 'gets_s') and 'rcx' in str(list(insns.values())[i].render()) or (funcname == 'WriteFile' or funcname == 'ReadFile') and 'rdx' in str(list(insns.values())[i].render()):
                                    arguments.append(str(list(insns.values())[i].render()).split('[')[2].split(']')[0])
    return arguments

def getaddrsource(proj: angr.Project, sourcefunc: int):
    initial_state = proj.factory.call_state(0x140001000)
    #initial_state = proj.factory.entry_state()
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    simulation = proj.factory.simgr(initial_state)
    @proj.hook(sourcefunc)
    def ok(state: angr.SimState):
        #if proj.arch == 'x86_64':
        print(state.mem[state.regs.rcx])
        print(state.mem[state.regs.rdx])
        print(state.regs.rdx)
        print(state.regs.edx)
        print(state.regs.eax)
        print(state.regs.r8d)
        proj.terminate_execution()

    simulation.run()


def Search(project: angr.Project, findaddr:int, sourceaddr: int, len: int):
    # Start in main()
    #initial_state = project.factory.entry_state()
    initial_state = project.factory.call_state(0x140001000)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    symb_vector = claripy.BVS('input', len * 8)
    initial_state.memory.store(sourceaddr, symb_vector)


    """TODO: Разобраться с эмулированием открытия файлов"""
    # filename = 'example.txt'
    # symbolic_file_size_bytes = 200
    #
    # # Create a BV which is going to be the content of the simbolic file
    # password = claripy.BVS('123', symbolic_file_size_bytes * 8)
    #
    # # Create the file simulation with the simbolic content
    # password_file = angr.storage.SimFile(filename, content=password)
    #
    # # Add the symbolic file we created to the symbolic filesystem.
    # initial_state.fs.insert(filename, password_file)

    # Start simulation
    simulation = project.factory.simgr(initial_state)



    # Find the way yo reach the good address
    good_address = findaddr


    # Avoiding this address
    #avoid_address = 0x140001087
    #simulation.use_technique(angr.exploration_techniques.Explorer(find=good_address))
    #simulation.run()
    # @project.hook(0x140001078)
    # def ok(state : angr.SimState):
    #     print(state.regs.rax)

    simulation.explore(find=good_address)

    # If found a way to reach the address
    if simulation.found:
        solution_state = simulation.found[0]
        win_sequence = ''
        finishedTracing = False
        for win_block in solution_state.history.bbl_addrs.hardcopy:
            win_block = project.factory.block(win_block)
            addresses = win_block.instruction_addrs
            for address in addresses:
                win_sequence += 't:' + hex(address) + '\n'
                if address == good_address:
                    # Prevent sending the rest of the block addresses that aren't desired
                    finishedTracing = True
                    break
            if finishedTracing:
                break
        win_sequence = win_sequence[:-1]
        #print(win_sequence)
        # Print the string that Angr wrote to stdin to follow solution_state
        #print(solution_state.posix.dumps(1))
        print(solution_state.solver.eval(symb_vector, cast_to=bytes))
        #print(solution_state.posix.dumps(sys.stdin.fileno()))
    else:
        print('Could not find the solution')