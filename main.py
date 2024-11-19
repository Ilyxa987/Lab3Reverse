import angr
import monkeyhex
from triton import *
from angrutils import *
import lief
import claripy
from StaticTableImports import *

import sys

filename = input("Введите название файла:\n")

""" Загрузка файла """
proj = angr.Project(filename, load_options={'auto_load_libs': False})

lib = [hex(x.rebased_addr) for x in proj.loader.main_object.imports.values()] # Загрузка таблицы импортов
print(lib)
""""""

""" Статическая загрузка всех адресов, где вызываются импортные функции """
call_imports = GetStaticImportAdderess(proj)

for key, value in call_imports.items():
    index = lib.index(hex(int(value, 0)))
    print(f"  0x{key:x} in lib", list(proj.loader.main_object.imports.keys())[index])
""""""

print(call_imports)

while True:
    funcnumber = int(input('Введите номер функции:\n1. Узнать аргументы\n2. Дойти до адреса(Нужен сурс)\n3. Узнать сурс\n'))

    if funcnumber == 1:
        funcname = input('Введите название функции:\n')
        args = FindArgs(funcname, call_imports, proj)
        print(args)

        if funcname == 'puts' or funcname == 'WriteFile':

            binary = lief.parse(filename)

            addri = 1
            for addr in args:
                print(addri, end='. ')
                for i in binary.get_content_from_virtual_address(int(addr, 0), 100):
                    if i == 0:
                        break
                    print(chr(i), end='')
                print()
                addri += 1
    elif funcnumber == 2:
        findaddr = int(str(input("Введите адрес\n")), 0)
        finsource = int(str(input('Введите адрес сурса\n')), 0)
        lensource = int(str(input('Введите длину\n')), 0)
        Search(proj, findaddr, finsource, lensource)

    elif funcnumber == 3:
        sourceaddr = int(str(input('Введите адрес сурса\n')), 0)
        getaddrsource(proj, sourceaddr)
    else:
        break

#print(proj.loader)

#print(proj.loader.all_objects)

# print(proj.loader.main_object)
#
# print(proj.loader.kernel_object)
#
# print(proj.loader.shared_objects)
#
# print(proj.loader.extern_object)

obj = proj.loader.main_object

# print(obj.segments)
#
# print(obj.find_segment_containing(0x140001000))

obj.imports["puts"]

# print('%x' % obj.imports['puts'].rebased_addr)
#
# print(proj.loader.find_symbol('puts'))
# print(proj.loader.find_symbol('puts'))
# print(proj.loader.find_symbol('puts'))
#
# print(proj.loader.find_symbol('gets_s'))
#
# print('%x' % obj.get_symbol('puts').rebased_addr)
#
# print('%x' % obj.get_symbol('gets_s').rebased_addr)

get_addr = obj.get_symbol('gets_s')

put_addr = obj.imports['puts'].rebased_addr #Надо достать массив значений
# По адресам коллов находить функции из импорта

# binary = lief.parse("test1.exe")

"""Проверка в статике"""
# instr1 = None
# for instr in proj.factory.fresh_block(0x140001000, 0xe1c).capstone.insns:
#     mnem = instr.mnemonic
#     if mnem == 'call':
#         if 'rip' in str(instr.op_str):
#             if (int(str(instr.op_str)[19:-1], 16) + instr.address + 6) == put_addr:
#                 print('puts here: %x' % instr.address)
#                 print('str here:', end=' ')
#                 for i in binary.get_content_from_virtual_address(int(str(instr1.op_str)[14:-1], 16) + instr1.address + 7, 100):
#                     if i == 0:
#                         break
#                     print(chr(i), end='')
#                 print()
#     if mnem == 'lea':
#         instr1 = instr



# state = proj.factory.blank_state(addr=0x140000000)
#
# state = proj.factory.call_state(0x140001000)
# state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
# state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
#
# @proj.hook(0x140001043)
# def ok(state):
#     print("asjfhbdhbsdhfbghjsdfg")

#simgr = proj.factory.simulation_manager(state)

# while simgr.active:
#     for state1 in simgr.active:
#         print(state1.block().disassembly)
#     simgr.step()

# cfg = proj.analyses.CFGEmulated()
# cfg.normalize()
#
#
# for func_node in cfg.functions.values():
#     print(func_node)
#     for block in func_node.blocks:
#         print('%x' % block.addr)

# @proj.hook(0x140001043)
# def ok(state):
#     print("jkdshjfasdf")
#
#
# proj.execute(state)



# binary = lief.parse("test1.exe")

# print(str(binary.get_content_from_virtual_address(0x140002268, 10)))
# print(proj.arch)
#
# print("0x%x" % proj.entry)
#
# print(proj.filename)
#
# print(proj.loader)
#
# print(proj.loader.shared_objects)
#
# function_manager = proj.kb.functions
#
# # Выводим адреса и имена функций
# for func_addr, func in function_manager.values():
#     print(f"Function address: {hex(func_addr)}, Name: {func.name}")

# state = proj.factory.
#
# simgr = proj.factory.simulation_manager(state)
#
# for state in simgr.active:
#     print(state.block().disassembly)
