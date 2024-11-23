import angr
from angrutils import *
import lief
import sys

#proj = angr.Project("test1.exe", arch='x86_64', load_options={'auto_load_libs': True})

def GetStaticImportAdderess(p : angr.Project):
    lib = [hex(x.rebased_addr) for x in p.loader.main_object.imports.values()]
    call_addresses = {}
    cfg = p.analyses.CFGFast()
    #cfg = p.analyses.CFGEmulated()
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

def getaddrsource(proj: angr.Project, sourcefunc: int, len: int):
    initial_state = proj.factory.call_state(0x140001000)
    #initial_state = proj.factory.entry_state()
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    initial_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    simulation = proj.factory.simgr(initial_state)

    @proj.hook(sourcefunc, length=len)
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
    # symbolic_file_size_bytes = 100
    # #
    # # # Create a BV which is going to be the content of the simbolic file
    # password = claripy.BVS('123', symbolic_file_size_bytes * 8)
    # #
    # # # Create the file simulation with the simbolic content
    # password_file = angr.storage.SimFile(filename, content=password)
    # #
    # # # Add the symbolic file we created to the symbolic filesystem.
    # initial_state.fs.insert(filename, password_file)
    #
    # # Start simulation
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