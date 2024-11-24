import lief
import claripy

encoded = []


def clear_encode():
    global encoded
    encoded = []


def add_encode(hook, string):
    global encoded
    encoded.append({hook: string})


def encode(lpSubKey_ptr, filename):
    flag = 0
    binary = lief.parse(filename)
    encode_str = ''

    for i in binary.get_content_from_virtual_address(int(lpSubKey_ptr), 100):
        if i != 0:
            flag = 0
            encode_str += chr(i)
        if i == 0:
            flag += 1
        if flag == 2:
            break
    return encode_str


def hook_reg_open_key_exw(state):
    hKey = state.solver.eval(state.regs.rcx)            # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)    # Второй аргумент (LPCWSTR)
    ulOptions = state.solver.eval(state.regs.r8)        # Третий аргумент (DWORD)
    samDesired = state.solver.eval(state.regs.r9)       # Четвертый аргумент (REGSAM)

    # Фиктивный дескриптор ключа (возвращаемое значение в phkResult)
    phkResult_ptr = state.mem[state.regs.rbp + 0x10].int.resolved

    add_encode("RegOpenKeyExW", encode(lpSubKey_ptr, "test3.exe"))
    print(encoded)

    # Логирование
    print(f"Hooked RegOpenKeyExW: "
          f"hKey={hKey}, lpSubKey_ptr={lpSubKey_ptr}, ulOptions={ulOptions}, samDesired={samDesired}")

    # Установка фиктивного значения для phkResult (например, дескриптор 0x1234)
    state.memory.store(phkResult_ptr, claripy.BVV(0x1234, 64))  # 64-битный дескриптор

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)


def hook_reg_query_value_exw(state):
    hKey = state.solver.eval(state.regs.rcx)                # Первый аргумент (HKEY)
    lpValueName_ptr = state.solver.eval(state.regs.rdx)     # Второй аргумент (LPCWSTR)
    lpReserved = state.solver.eval(state.regs.r8)           # Третий аргумент
    lpType_ptr = state.solver.eval(state.regs.r9)           # Четвертый аргумент

    # Имитация данных о результатах запроса реестра
    lpData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x30, 8))

    # Логирование
    print(f"Hooked RegQueryValueExW: "
          f"hKey={hex(hKey)}, lpValueName_ptr={hex(lpValueName_ptr)}")

    # Имитация установки типа (например, REG_SZ = 1)
    state.memory.store(lpType_ptr, claripy.BVV(1, 32))

    # Write sample data ("TestValue" in WCHAR)
    test_value = "TestValue".encode('utf-16le')  # Convert to UTF-16 for Windows registry strings
    for i, b in enumerate(test_value):
        state.memory.store(lpData_ptr + i, claripy.BVV(b, 8))  # Write each byte

    # Set the size of the returned data
    state.memory.store(pcbData_ptr, claripy.BVV(len(test_value), 32))

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 64)  # Возвращает 0 (успех)


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
    print(9)
"""


def hook_reg_get_value_w(state):
    hKey = state.solver.eval(state.regs.rcx)            # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)    # Второй аргумент (LPCWSTR)
    lpValue_ptr = state.solver.eval(state.regs.r8)      # Третий аргумент
    dwFlags = state.solver.eval(state.regs.r9)          # Четвертый аргумент (флаги)

    add_encode("RegGetValueW", encode(lpValue_ptr, "test3.exe"))
    print(encoded)

    lpData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x40, 8))
    print(hex(lpData_ptr), hex(pcbData_ptr))

    # Логирование
    print(f"Hooked RegGetValueW: "
          f"hKey={hex(hKey)}, lpSubKey_ptr={hex(lpSubKey_ptr)}, lpValue_ptr={hex(lpValue_ptr)}, dwFlags={dwFlags}")

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 32)  # Возвращает 0 (успех)


def hook_reg_set_value_exw(state):
    hKey = state.solver.eval(state.regs.rcx)            # Первый аргумент (HKEY)
    lpSubKey_ptr = state.solver.eval(state.regs.rdx)    # Второй аргумент (LPCWSTR)
    lpValue_ptr = state.solver.eval(state.regs.r8)      # Третий аргумент
    dwFlags = state.solver.eval(state.regs.r9)          # Четвертый аргумент (флаги)

    add_encode("RegSetValueW", encode(lpSubKey_ptr, "test3.exe"))
    print(encoded)

    # Извлечь дополнительные аргументы из стека
    pdwType_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x28, 8))  # Указатель на тип (REG_*)
    pvData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x30, 8))  # Указатель на буфер данных
    pcbData_ptr = state.solver.eval(state.memory.load(state.regs.rsp + 0x38, 8))  # Указатель на размер данных

    # Логирование
    print(
        f"Hooked RegSetValueW: "
        f"hKey={hex(hKey)}, lpSubKey_ptr={hex(lpSubKey_ptr)}, lpValue_ptr={hex(lpValue_ptr)}, "
        f"{dwFlags, pdwType_ptr, hex(pvData_ptr), hex(pcbData_ptr)}")

    # Simulate returning the type (e.g., REG_SZ = 1 for string data)
    #   state.memory.store(pdwType_ptr, claripy.BVV(1, 32))  # Assume REG_SZ type (string)

    # Simulate returning some mock data (for example, "TestValue" in WCHAR/UTF-16)
    test_data = "TestValue".encode('utf-16le')
    for i, byte in enumerate(test_data):
        state.memory.store(pvData_ptr + i, claripy.BVV(byte, 8))  # Write each byte of the string

    # Set the data size (number of bytes written)
    state.memory.store(pcbData_ptr, claripy.BVV(len(test_data), 32))

    # Возвращаемый результат (ERROR_SUCCESS = 0)
    state.regs.rax = claripy.BVV(0, 32)  # Возвращает 0 (успех)


def hook_some(state):
    print(state.regs.rsp)
    print(9999)
