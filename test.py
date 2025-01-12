import angr
import claripy



from angr import *
import capstone
import re  # Для работы с регулярными выражениями

from Hooks import hook_readconsole, hook_writeconsole
from StaticTableImports import GetStaticImportAdderess
from test_lib import *
def default_hook(state):
    """
    Дефолтный хук для всех внешних функций.
    """
    func_name = state.addr
    print(f"[HOOK] Внешний вызов функции по адресу: 0x{func_name:x}")

def set_default_hooks(proj: angr.Project):
    """
    Устанавливает дефолтные хуки для всех внешних функций.
    """
    # Перебираем все импортированные функции
    for func in proj.loader.main_object.imports.values():
        addr = func.rebased_addr
        try:
            # Устанавливаем хук для этой функции
            proj.hook(addr, default_hook)
            print(f"[HOOK SET] Установлен дефолтный хук для функции по адресу 0x{addr:x}")
        except Exception as e:
            print(f"[ERROR] Не удалось установить хук для функции по адресу 0x{addr:x}: {e}")

def find_call_with_push(proj: angr.Project):
    """
    Ищет последовательности `push offset` -> `call <адрес>` в исполняемом файле.
    Если в `push` встречается символ %, возвращается адрес.

    :param proj: Объект проекта angr
    :return: Список адресов вызовов, где найдены такие последовательности
    """
    found_calls = []

    # Итерация по всем исполняемым сегментам файла
    for segment in proj.loader.main_object.segments:
        if segment.is_executable:
            start_addr = segment.vaddr
            end_addr = start_addr + segment.memsize

            for addr in range(start_addr, start_addr+0x001900):  # Переход по блокам
                try:
                    block = proj.factory.block(addr)
                    insns = list(block.capstone.insns)  # Получение инструкций
                    # Поиск последовательности `push` -> `call`
                    for i in range(len(insns) - 1):
                        if insns[i].mnemonic == "push":
                            # Проверка на наличие % в операнде push
                            operand = insns[i].op_str
                            addr_value = int(operand, 16)  # Преобразуем операнд в целое число
                            # Получаем значение по этому адресу
                            data = proj.loader.memory.load(addr_value, 4)
                            percent_index = str(data).find("%")  # Находим позицию '%'
                            if "%" in str(data) and str(data[1]).isdigit() and int(str(data)[percent_index+1]) != '0':
                                print(data)
                                found_calls.append((insns[i].address, insns[i + 1].address))
                                print(f"[FOUND] push с %: 0x{insns[i].address:x}, call: 0x{insns[i + 1].address:x}")
                                return found_calls  # Возвращаем результат сразу, если нашли соответствующий push
                            if "Ente" in str(data) and len(str(data))>4:
                                print(data)
                                print(f"[FOUND] push с %: 0x{insns[i].address:x}, call: 0x{insns[i + 1].address:x}")
                                found_calls.append((insns[i].address, insns[i + 1].address))
                except Exception:
                    continue

    return found_calls


def get_addr_symb_vector(proj, addr_func, addr_start=0x4017D0):
    initial_state = proj.factory.call_state(addr_start)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    # Создаем симуляционный менеджер
    simgr = proj.factory.simulation_manager(initial_state)

    symb_addr = []
    @proj.hook(addr_func)
    def ok(state: angr.SimState):
        print('scan')
        print(state.stack_pop())
        addr = str(state.stack_pop())
        ind = addr.find("0x")
        symb_addr.append(addr[ind:len(addr) - 1])
        state.add_constraints(claripy.BoolV(False))  # Принудительная остановка
        state.history.jumpkind = "Ijk_Exit"
        state.project.terminate_execution()

    simulation = proj.factory.simgr(initial_state)

    simulation.run()
    return symb_addr


def angr_explore(proj: angr.Project, addr_start=0x4017D0, addr_vector=0x7fffffffffeff50, addr_find=0x140001087):

    initial_state = proj.factory.call_state(addr_start)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)



    symb_vector=[0]*len(addr_vector)

    j = 0
    for i in addr_vector:
        symb_vector[j] = claripy.BVS('input', 40 * 8)
        #0xB8FC34#41EF48#41EF48#41EF4C
        for k in range(39):  # Длина строки 40 символов
            #initial_state.solver.add(symb_vector[j].get_byte(k) != ord('b'))
            initial_state.solver.add(symb_vector[j].get_byte(k) == ord('0'))
            #initial_state.solver.add(symb_vector[j].get_byte(k) <= ord('Z'))

        initial_state.memory.store(int(hex(int(i[0], 0)), 16), symb_vector[j])
        j += 1

    #initial_state.memory.store(0x7FFFFFFFFFEFEc0, symb_vector)

    initial_state.options.discard(angr.options.TRACK_ACTION_HISTORY)
    initial_state.options.discard(angr.options.CONSERVATIVE_READ_STRATEGY)

    initial_state.options.discard(angr.options.NO_SYMBOLIC_JUMP_RESOLUTION)
    initial_state.options.discard(angr.options.NO_CROSS_INSN_OPT)
    initial_state.options.discard(angr.options.NO_IP_CONCRETIZATION)
    initial_state.options.discard(angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION)


    '''initial_state.options.discard(angr.options.NO_CROSS_INSN_OPT)

    initial_state.options.discard(angr.options.NO_SYMBOLIC_JUMP_RESOLUTION)
    initial_state.options.discard(angr.options.AVOID_MULTIVALUED_READS)'''

    simulation = proj.factory.simgr(initial_state)

    simulation.explore(find=addr_find)
    #simulation.explore(find=0x140001094)

    if simulation.found:
        solution_state = simulation.found[0]
        win_sequence = ''
        finishedTracing = False
        for win_block in solution_state.history.bbl_addrs.hardcopy:
            win_block = proj.factory.block(win_block)
            addresses = win_block.instruction_addrs
            for address in addresses:
                win_sequence += 't:' + hex(address) + '\n'
                if address == addr_find:
                    # Prevent sending the rest of the block addresses that aren't desired
                    finishedTracing = True
                    break
            if finishedTracing:
                break
        win_sequence = win_sequence[:-1]
        # print(win_sequence)
        # Print the string that Angr wrote to stdin to follow solution_state
        # print(solution_state.posix.dumps(1))
        for ind in range(j):
            print(solution_state.solver.eval(symb_vector[ind], cast_to=bytes))
        # print(solution_state.posix.dumps(sys.stdin.fileno()))
    else:
        print('Could not find the solution')
    print()


def find_printf(proj: angr.Project, target_address):
    found_calls = None

    block = proj.factory.block(target_address)  # Загружаем блок по адресу

    # Используем Capstone для анализа инструкций в блоке
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # Архитектура x86-64
    instructions = list(md.disasm(block.bytes, block.addr))

    for instr in instructions:
        if instr.address == target_address and instr.mnemonic == "call":
            found_calls = instr.op_str
            print(f"Найдена инструкция вызова: {instr.mnemonic} {instr.op_str} на 0x{instr.address:x}")
            break



    binary = proj.loader.main_object

    # Используем Capstone для дизассемблирования
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # Архитектура x86
    md.detail = True

    # Проход по всем блокам в пределах исполняемого диапазона
    start_address = binary.min_addr
    end_address = binary.max_addr

    addr_res = []
    print(f"Диапазон анализа: 0x{start_address:x} - 0x{end_address:x}")
    for addr in range(start_address, end_address):
        try:
            # Загружаем блок по адресу
            block = proj.factory.block(addr)
            instructions = list(md.disasm(block.bytes, block.addr))

            # Проходимся по инструкциям в блоке
            for instr in instructions:
                if instr.mnemonic == "call" and instr.op_str==found_calls:
                    # Проверяем, есть ли перед вызовом `push offset`
                    idx = instructions.index(instr)
                    if idx > 0 and instructions[idx - 1].mnemonic == "push":
                        try:
                            offset = int(instructions[idx - 1].op_str, 16)
                        except:
                            continue
                        if instr.address in addr_res:
                            continue
                        addr_res.append(instr.address)
                        print(f"Найдена инструкция `call` на 0x{instr.address:x}: {instr.op_str}")

                        print(f"  Найден `push` перед вызовом: offset=0x{offset:x}")

                        # Попытка извлечь содержимое по указанному адресу
                        try:
                            content = proj.loader.memory.load(offset, 100)  # Читаем до 100 байт
                            content_str = content.split(b'\x00')[0].decode("utf-8", errors="ignore")
                            print(f"  Содержимое offset: {content_str}")
                        except Exception as e:
                            print(f"  Ошибка извлечения содержимого: {e}")
                        print("-" * 80)
        except Exception:
            continue

def patch_nop(addr, bytes, pm):
    patch_data = b'\x90' * bytes
    pm.add_patch(addr, patch_data)


def bin_save(file_name, pm):
    patched_data = pm.apply_patches_to_binary()
    with open(file_name, "wb") as patched_file:
        patched_file.write(patched_data)

def find_div_ch(proj):
    """
    Ищет инструкции `div ch` во всех блоках бинарного файла.

    :param file_name: Имя бинарного файла для анализа.
    """
    # Загрузка бинарного файла в angr
    binary = proj.loader.main_object

    # Используем Capstone для дизассемблирования
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # Архитектура x86
    md.detail = True

    # Проход по всем блокам в пределах исполняемого диапазона
    start_address = binary.min_addr
    end_address = 0x4119e8

    print(f"Диапазон анализа: 0x{start_address:x} - 0x{end_address:x}")
    find_addr = []
    for addr in range(start_address, end_address):
        try:
            # Загружаем блок по адресу
            block = proj.factory.block(addr)
            instructions = list(md.disasm(block.bytes, block.addr))

            # Проходимся по инструкциям в блоке
            for i, instr in enumerate(instructions):
                if instr.mnemonic == "div" and instr.op_str == "ch" and instr.address not in find_addr:
                    # Проверяем предыдущую инструкцию, если она есть
                    if i > 0:
                        prev_instr = instructions[i - 1]
                        if prev_instr.mnemonic == "mov" and prev_instr.op_str == "ecx, 0":
                            find_addr.append(instr.address)
                            print(
                                f"Найдена инструкция `div ch` на 0x{instr.address:x} после `mov ecx, 0` на 0x{prev_instr.address:x}")
                            print(f"  Предыдущая инструкция: {prev_instr.mnemonic} {prev_instr.op_str}")
                            print("-" * 80)
        except Exception:
            continue
    return find_addr
def func_patch(proj: angr.Project, file_name):
    find_addr = find_div_ch(proj)

    call_imports = GetStaticImportAdderess(proj)
    address_names = dict()

    lib = [hex(x.rebased_addr) for x in proj.loader.main_object.imports.values()]  # Загрузка таблицы импортов
    print(lib)

    patch_hooks = {'IsDebuggerPresent': 6}
    pm = proj.kb.patches

    for key, value in call_imports.items():
        index = lib.index(hex(int(value, 0)))
        if list(proj.loader.main_object.imports.keys())[index] in patch_hooks.keys():
            patch_nop(key, patch_hooks[list(proj.loader.main_object.imports.keys())[index]], pm)
            print("Пропатчен", list(proj.loader.main_object.imports.keys())[index])

    for i in find_addr:
        patch_nop(i, 2, pm)
        print("Пропатчен dih", hex(i))

    bin_save("patch_"+file_name, pm)


if __name__ == "__main__":
    #имя файла
    file_name = input("file_name:  ")
    proj = angr.Project(file_name, auto_load_libs=False)

    #патчинг
    func_patch(proj,file_name)

    # Установка хуков
    set_default_hooks(proj)

    # Поиск последовательностей push -> call
    calls = find_call_with_push(proj)
    addr =None
    push_offset_addr = None
    # Вывод результатов
    print(calls)
    if calls:
        for push_addr, call_addr in calls:
            addr = call_addr
            push_offset_addr = push_addr
            print(f"  push по адресу: 0x{push_addr:x}, call по адресу: 0x{call_addr:x}")
    else:
        print("Последовательности `push offset` -> `call` не найдены.")

    proj.hook(calls[0][1], hook_readconsole, 5)

    symb = []
    print(hex(calls[0][1]))
    print(hex(calls[len(calls)-1][1]))
    symb.append(get_addr_symb_vector(proj, addr_func=calls[len(calls)-1][1], addr_start=0x4017F0))#0x004017D0

    print(symb)



    '''выводит printf и их содержимое'''
    proj = angr.Project(file_name, auto_load_libs=False)
    #set_default_hooks(proj)
    proj.hook(calls[0][1], hook_readconsole, 5)
    proj.hook(calls[len(calls)-1][1], hook_writeconsole, 5)

    find_printf(proj, calls[0][1])
    #proj.hook(int("0x401B06",0), hook_writeconsole, 5)


    #angr_explore(proj, addr_start=0x4017D0, addr_vector=symb, addr_find=0x401B21)
    #0x4017D0 - начало проги
    #0x401450 - начало проверки пароля
    #0x401A63 - последний символ
    #0x401B25 - остаток
    #0x4015D0 - возвращает 1

