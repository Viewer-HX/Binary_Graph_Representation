'''
    This script 1) disassembles the patched and unpatched binary (.o) files via angr and
    2) then extracts patched and unpatched sub CFG, CDG, DDG, slicing code snippets.
'''

import os
import re
import logging
import gc
import datetime
import traceback
import utility
from func_timeout import FunctionTimedOut, func_set_timeout
import eventlet
import angr
from angrutils import *
import sys

# patchesDir = "../test/"
# commits_dir = "/home/binaryf/Binary_database/Crawler/KernelSecurityDatasetx86v4"
# commits_dir = "/home/binaryf/Binary_database/SecretPatch/nonSecurityDatasetv1"
commits_dir = "/home/xu/SoftwarePatch/judged/negatives/divided"
patch_meta = "patch_info.txt"

patched_funcs_assembly_info = "patched_funcs_assembly_info.txt"
patched_funcs_binary_info = "patched_funcs_binary_info.txt"
binary_subgraph_success_info = "patch_subgraph_success"

timeout_commits = ["3509a03f4dcf7fedb8880180fed3f7f791ce5598",
                   "196f954e250943df414efd3d632254c29be38e59"]

built_projects = ["openssl", "libav"]

# Recording in different log files
log_file_name = "patched-slicing-code-info.log"
idx = 0
while os.path.exists("Log/" + log_file_name + str(idx)):
    idx = idx + 1
log_file_name = log_file_name + str(idx)
# logger.basicConfig(level=logger.DEBUG,
#                     filename="tmp/"+ log_file_name,
#                     filemode='w')

logger = logging.getLogger('log')
logger.setLevel(logging.INFO)

fh = logging.FileHandler("Log/" + log_file_name, encoding='utf-8')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)


# Extract meta information of patch from "patch_info.txt"
def patched_source_code_lines_extract(patch_meta_path):
    patched_func_to_lines = {}
    patched_func_to_file_Idx = {}

    patched_info = utility.file_to_object(patch_meta_path)
    modified_files = patched_info["modifyFiles"]
    modified_funcs = patched_info["modifyFuncs"]

    # if len(modified_files) > 1:
    #     logger.info("Currently, we only handle modifications in one patched source code file.")
    #     return {}, {}, {}, {}

    for idx in modified_files:
        if len(modified_funcs[idx]) != 0:
            for funcs in modified_funcs[idx]:
                # logger.info(funcs["function"])

                # The string parsing of function name
                func_name = funcs["function"]
                if func_name.count(" ") > 0:
                    func_name = func_name[func_name.rindex(" ") + 1:]
                if func_name.count("*") > 0:
                    func_name = func_name[func_name.index("*") + 1:]

                num = 1
                patched_all_lines = []
                patched_lines = {}
                if func_name in patched_func_to_lines:
                    patched_all_lines = patched_func_to_lines[func_name]
                    num = len(patched_all_lines) + 1
                if func_name not in patched_func_to_file_Idx:
                    patched_func_to_file_Idx[func_name] = idx

                # logger.info(funcs["after"])
                # logger.info(funcs["before"])
                # Extract patched and unpatched line numbers
                if funcs["after"].index(",") != -1:
                    lines = funcs["after"].split(",")
                    start = lines[0][1:]
                    end = lines[1]
                    end = int(start) + int(end) - 1
                    patched_lines["after"] = {"start": start, "end": end}
                    # patched_lines["after"] = {"start": 966, "end": 969}

                if funcs["before"].index(",") != -1:
                    lines = funcs["before"].split(",")
                    start = lines[0][1:]
                    end = lines[1]
                    end = int(start) + int(end) - 1
                    patched_lines["before"] = {"start": start, "end": end}
                    # patched_lines["before"] = {"start": 977, "end": 980}

                patched_all_lines.append({"modifyIndex": num, "line": patched_lines})
                patched_func_to_lines[func_name] = patched_all_lines

    return modified_files, modified_funcs, patched_func_to_file_Idx, patched_func_to_lines


# Extract patched assembly codes from intel assembly files with debug information (.loc)
def extract_patched_assembly_code_from_debug_file(patched_assembly_file, patched_func,
                                                  patched_lines_info, patched_tag):
    logger.info("The extraction of patched assembly codes from file: {}---{}---{}"
                .format(patched_assembly_file, patched_func, patched_tag))
    patched_func_id = ""

    inst_count = 0
    inst_idx = 0

    patched_func_flag = False

    patched_func_insts = []
    patched_func_inst_to_opcode = {}
    patched_func_inst_to_operand = {}
    patched_func_inst_to_debug = {}

    cur_debug_info = {}

    with open(patched_assembly_file, "r") as af:
        lines = af.readlines()
        # logger.info(len(lines))
        for i in range(0, len(lines) - 1):
            line = lines[i]  # .strip()
            # logger.info(line)
            # the start sign of patched function in assembly files
            if not line.startswith(".") \
                    and not line.startswith("#") \
                    and ".loc" not in line:
                # logger.info(line)
                inst_count = inst_count + 1
            if line.startswith(patched_func + ":"):
                # logger.info("vulnerable functions")
                patched_func_flag = True
                patched_func_id = re.findall('\d+', lines[i + 1])[0]
                logger.info("function id: " + str(patched_func_id))
                logger.info("function flag: " + str(patched_func_flag))
                continue
            # the enter into patched function
            if patched_func_flag:
                # the stop sign of patched function in assembly files
                if line.startswith(".Lfunc_end" + patched_func_id) \
                        or line.startswith(".LFE" + patched_func_id):
                    patched_func_flag = False
                    break
                debug_line = line.strip()
                # logger.info(debug_line)
                # the string parse to extract patched line number from assembly files
                if debug_line.startswith(".loc") or ".loc " in debug_line:
                    # logger.info(debug_line)
                    if debug_line.count("\t") > 0:
                        debug_line = debug_line.split('\t')[1].split(' ')
                        cur_debug_info = {"line": debug_line[1],
                                          "col": debug_line[2],
                                          "other": debug_line[3]}
                    elif debug_line.count(" ") > 0:
                        debug_line = debug_line.split(' ')
                        # logger.info(debug_line)
                        cur_debug_info = {"line": debug_line[2],
                                          "col": debug_line[3],
                                          "other": debug_line[1]}
                    else:
                        cur_debug_info = {"info": debug_line.strip()}
                    # logger.info(cur_debug_info)
                    continue
                # the string parse of assembly instructions
                if not line.strip().startswith(".") and not line.strip().startswith("#"):
                    if ',' in line:
                        line = re.sub('(?P<number>\d+)', utility.int_to_hex, line)
                    patched_func_insts.append(line.strip())
                    # logger.info(line.split('\t'))
                    if line.count('\t') == 0:
                        continue
                    try:
                        opcode = line.split('\t')[1].strip()
                        patched_func_inst_to_opcode[inst_idx] = opcode
                        operand = ""
                        if len(line.split('\t')) > 2:
                            operand = line.split('\t')[2].strip()
                        patched_func_inst_to_operand[inst_idx] = operand
                    except Exception as e:
                        logger.info("Opcode error information: {}.".format(str(e)))
                    # logger.info(line)
                    patched_func_inst_to_debug[inst_idx] = cur_debug_info
                    inst_idx = inst_idx + 1

    logger.info("There are {} instructions for function: {} in intel assembly files.".
                format(str(len(patched_func_insts)), patched_func))
    # logger.info(len(patched_func_inst_to_opcode))
    # logger.info(len(patched_func_inst_to_operand))
    # logger.info(len(patched_func_inst_to_debug))
    # logger.info(patched_func_inst_to_debug)
    # logger.info(inst_count)

    patched_assembly_insts_to_Idx = []
    logger.info(patched_lines_info)
    # build the mapping from assembly instruction to instruction sequence
    for patched_lines in patched_lines_info:
        each_patched_assembly_insts_Idx = []
        start = int(patched_lines["line"][patched_tag]["start"])
        end = int(patched_lines["line"][patched_tag]["end"])

        for idx in patched_func_inst_to_debug:
            if "line" in patched_func_inst_to_debug[idx]:
                line = patched_func_inst_to_debug[idx]["line"]
                # logger.info(line)
                if start <= int(line) <= end:
                    # logger.info(idx)
                    each_patched_assembly_insts_Idx.append(idx)
                    # logger.info(patched_func_insts[idx])
        patched_assembly_insts_to_Idx.append({"modifyIndex": patched_lines["modifyIndex"],
                                              "patched_tag": patched_tag,
                                              "instIndexInfo": each_patched_assembly_insts_Idx})
    # logger.info(patched_assembly_insts_to_Idx)

    empty_flag = True
    # the storage of patched instructions and their sequences
    patched_func_to_assembly_insts = []
    for info in patched_assembly_insts_to_Idx:
        insts_info = []
        for idx in info["instIndexInfo"]:
            # insts_info.append({"instIndex":idx,
            # "instruction":patched_func_insts[idx],
            # "debug_info":patched_func_inst_to_debug[idx]})
            insts_info.append({"instIndex": idx,
                               "instruction": patched_func_insts[idx]})
        if insts_info != []:
            empty_flag = False
        patched_func_to_assembly_insts.append({"modifyIndex": info["modifyIndex"],
                                               "patched_tag": patched_tag,
                                               "insts_info": insts_info})
    logger.info(patched_func_to_assembly_insts)

    return patched_func_to_assembly_insts, empty_flag

@func_set_timeout(20*60)
# Perform cfg task
def cfg_task(prog, patchedFunc):
    cfg = prog.analyses.CFGFast(function_starts=[patchedFunc.rebased_addr])
    return cfg

# Extract patched or unpatched assembly code snippets, CFG from binaries via angr
def extract_patched_assembly_code_from_binary_file_angr(patched_binary_file,
                                                        patched_funcs_to_assembly_insts,
                                                        patched_tag):
    logger.info("The extraction of assembly code from binary: {}---{}"
                .format(patched_binary_file, patched_tag))
    start = datetime.datetime.now()

    # logger.info(patched_binary_file)
    # extract CFG information
    prog = angr.Project(patched_binary_file,
                        load_options={'auto_load_libs': False})
    # logger.info("Analyzing the binaries to generate CFGs and CGs ...")
    # cfg = {}
    # with eventlet.Timeout(30*60, False):
    #     cfg = prog.analyses.CFGFast()
    # if cfg == {}:
    #     return {}
    # cg = cfg.functions.callgraph
    # logger.info("The CFGs and CGs Analysis have been finished ...")

    patched_funcs_to_sub_graph = {}
    patched_funcs_to_patched_block_addrs = {}

    empty_flag = True

    for patched_func in patched_funcs_to_assembly_insts:

        logger.info("The extraction of function: {}".format(patched_func))
        patchedFunc = prog.loader.main_object.get_symbol(patched_func)
        if patchedFunc is None:
            logger.info("There is no function: {} in binary {}".
                        format(patched_func, patched_binary_file))
            continue
        logger.info("Analyzing the binaries to generate subCFGs from patched function ...")
        cfg = {}
        try:
            cfg = cfg_task(prog, patchedFunc)
        except FunctionTimedOut:
            logger.info("The construction of CFG can not complete in 30 minutes and was terminated.")
        # eventlet.monkey_patch()
        # with eventlet.Timeout(30 * 60, False):
        #     cfg = prog.analyses.CFGFast(function_starts=[patchedFunc.rebased_addr])
        if cfg == {}:
            continue
        logger.info("It has %d nodes and %d edges in CFGFast" %
                    (len(cfg.graph.nodes()), len(cfg.graph.edges())))
        cg = cfg.functions.callgraph
        logger.info("The subCFGs and subCGs Analysis have been finished ...")

        inst_Idx = 0
        block_Idx = 0
        block_to_Idx = {}
        idx_to_block = {}
        addr_to_block = {}

        func_addrs = []
        func_edges = set(())

        # build the mapping between instruction and their sequence
        for idx, func in enumerate(list(cg.nodes)):
            function = cfg.functions.function(func)
            # if patched_func in function.name:
            if patched_func == function.name:
                for block in function.blocks:
                    if block is not None:
                        for addr in block.instruction_addrs:
                            func_addrs.append(int(addr))
                        addr_to_block[int(block.addr)] = block
                        idx_to_block[block_Idx] = block
                        block_to_Idx[block] = block_Idx
                        inst_Idx = inst_Idx + block.instructions
                        block_Idx = block_Idx + 1

                for edge in function.graph.edges:
                    func_edges.add((block_to_Idx[addr_to_block[int(edge[0].addr)]],
                                    block_to_Idx[addr_to_block[int(edge[1].addr)]]))

        func_addrs = list(set(func_addrs))
        func_addrs = sorted(func_addrs)
        logger.info("There are " + str(len(func_addrs)) + " instructions in binary file.")

        patched_funcs_to_sub_graph[patched_func] = []
        for func_to_assembly_insts in patched_funcs_to_assembly_insts[patched_func]:
            # extract patched instruction addresses according to instruction sequences
            patched_addrs = []
            # patched_insts_to_addrs = []
            # logger.info(func_to_assembly_insts)
            # {"modifyIndex":"", "patched_tag":"", "insts_info":""}
            for inst_info in func_to_assembly_insts["insts_info"]:
                try:
                    patched_addrs.append(func_addrs[inst_info["instIndex"]])
                    # patched_insts_to_addrs.append({"instIndex": inst_info["instIndex"],
                    # "address": func_addrs[inst_info["instIndex"]]})
                except Exception as e:
                    logger.info("Angr error information: " + str(e))

            sorted_addr_to_block = sorted(addr_to_block.items(), key=lambda x: x[0])

            # extract patched block information according to patched instruction addresses
            patched_blocks = []
            patched_block_addrs = []
            for addr, block in sorted_addr_to_block:
                for addr in patched_addrs:
                    if addr in block.instruction_addrs:
                        if block not in patched_blocks:
                            patched_blocks.append(block)
                            patched_block_addrs.append(block.addr)
            # extract subgraph control flow graph information from binary
            patched_block_addrs = sorted(list(set(patched_block_addrs)))
            patched_funcs_to_patched_block_addrs[patched_func] = patched_block_addrs
            # patched_addrs = sorted(patched_addrs)
            logger.info(patched_block_addrs)

            patched_blocks_to_insts = []
            patched_edge_info = set(())
            patch_related_blocks = []
            # logger.info("patched block information:")
            # block.addr, block.capstone.insns, block["ops"], block.pp()
            # the extraction of patch related blocks and edges
            for block in patched_blocks:
                # block.pp()
                patch_related_blocks.append(block)
                for edge in func_edges:
                    # logger.info(edge)
                    # logger.info(block)
                    if block_to_Idx[block] in edge:
                        patched_edge_info.add(edge)
                        patch_related_blocks.append(idx_to_block[edge[0]])
                        patch_related_blocks.append(idx_to_block[edge[1]])
            patch_related_blocks = list(set(patch_related_blocks))

            patched_blocks_to_insts_detailed = []
            # the storage of subgraph edges information
            for block in patch_related_blocks:
                patched_blocks_to_insts.append({"block_Idx": block_to_Idx[block],
                                                "blockInsts": str(block.capstone.insns)})
                insns_info = []
                for insn in block.capstone.insns:
                    insns_info.append("<" + str(insn.mnemonic) + "~~"
                                      + str(insn.op_str) + ">")
                patched_blocks_to_insts_detailed.append({"block_Idx": block_to_Idx[block],
                                                         "blockInsts": insns_info})
            # logger.info(patched_blocks_to_insts)
            # logger.info(patched_edge_info)
            patched_funcs_to_sub_graph[patched_func]. \
                append({"patched_tag": patched_tag,
                        "cfg_block_info": patched_blocks_to_insts,
                        "cfg_block_detailed_info": patched_blocks_to_insts_detailed,
                        "cfg_edge_info": list(patched_edge_info)})

            if patched_blocks_to_insts != [] and patched_edge_info != []:
                empty_flag = False
        # logger.info(patched_funcs_to_sub_graph[patched_func])
    # logging.info(patched_funcs_to_sub_graph)
    # print(patched_funcs_to_sub_graph)
    gc.collect()
    end = datetime.datetime.now()
    logger.info("The execution time of patched subCFG information extraction via angr: {}".
                format(str(end - start)))

    return patched_funcs_to_sub_graph, empty_flag, \
           patched_funcs_to_patched_block_addrs

@func_set_timeout(20*60)
# Perform cfgEmulated task
def cfgEmulated_task(prog, patchedFunc, patchedState):
    cfgE = prog.analyses.CFGEmulated(starts=[patchedFunc.rebased_addr],
                                     initial_state=patchedState,
                                     context_sensitivity_level=2,
                                     keep_state=True,
                                     state_add_options=angr.sim_options.refs)
    return cfgE

@func_set_timeout(20*60)
# Perform cdg task
def cdg_task(prog, patchedFunc, cfgE):
    cdg = prog.analyses.CDG(cfgE, start=patchedFunc.rebased_addr)
    return cdg

@func_set_timeout(20*60)
# Perform ddg task
def ddg_task(prog, patchedFunc, cfgE):
    ddg = prog.analyses.DDG(cfgE, start=patchedFunc.rebased_addr)
    return ddg

# Extract patched or unpatched assembly CDG, DDG and slicing information from binaries via angr
def extract_patched_assembly_code_from_binary_file_angr2(patched_binary_file,
                                                         patched_funcs_to_patched_block_addrs,
                                                         patched_tag):
    logger.info("The extraction of slicing assembly code from binary: {}---{}"
                .format(patched_binary_file, patched_tag))
    start = datetime.datetime.now()

    # logger.info(patched_binary_file)N
    # extract CFG information
    prog = angr.Project(patched_binary_file, load_options={'auto_load_libs': False})
    patched_funcs_to_slicing_info = {}

    empty_flag = True

    for patched_func in patched_funcs_to_patched_block_addrs:

        logger.info("The extraction of function: {}".format(patched_func))

        patchedFunc = prog.loader.main_object.get_symbol(patched_func)
        if patchedFunc is None:
            logger.info("There is no function: {} in binary {}".
                        format(patched_func, patched_binary_file))
            continue

        patched_block_addrs = patched_funcs_to_patched_block_addrs[patched_func]
        logger.info(patched_block_addrs)
        patchedState = prog.factory.blank_state(addr=patchedFunc.rebased_addr)

        logger.info("Analyzing the binaries to generate subCFGs "
                    "starting from patched function...")
        cfgE = {}
        try:
            cfgE = cfgEmulated_task(prog, patchedFunc, patchedState)
        except FunctionTimedOut:
            logger.info("The construction of CFGEmulated can not complete in 30 minutes and was terminated.")
        # eventlet.monkey_patch()
        # with eventlet.Timeout(20 * 60, False):
        #     cfgE = prog.analyses.CFGEmulated(starts=[patchedFunc.rebased_addr],
        #                                      initial_state=patchedState,
        #                                      context_sensitivity_level=2,
        #                                      keep_state=True,
        #                                      state_add_options=angr.sim_options.refs)
        if cfgE == {}:
            continue

        logger.info("Analyzing the binaries to generate subCDGs "
                    "starting from patched function...")
        cdg = {}
        # eventlet.monkey_patch()
        # with eventlet.Timeout(20 * 60, False):
        #     cdg = prog.analyses.CDG(cfgE, start=patchedFunc.rebased_addr)
        try:
            cdg = cdg_task(prog, patchedFunc, cfgE)
        except FunctionTimedOut:
            logger.info("The construction of CDG can not complete in 30 minutes and was terminated.")
        if cdg == {}:
            continue

        logger.info("Analyzing the binaries to generate subDDGs "
                    "starting from patched function...")
        ddg = {}
        try:
            ddg = ddg_task(prog, patchedFunc, cfgE)
        except FunctionTimedOut:
            logger.info("The construction of DDG can not complete in 30 minutes and was terminated.")
        # eventlet.monkey_patch()
        # with eventlet.Timeout(20 * 60, False):
        #     ddg = prog.analyses.DDG(cfgE, start=patchedFunc.rebased_addr)
        if ddg == {}:
            continue

        logger.info("It has %d nodes and %d edges in CFGEmulated."
                    % (len(cfgE.graph.nodes()), len(cfgE.graph.edges())))
        logger.info("It has %d nodes and %d edges in CDG."
                    % (len(cdg.graph.nodes()), len(cdg.graph.edges())))
        logger.info("It has %d nodes and %d edges in DDG."
                    % (len(ddg.graph.nodes()), len(ddg.graph.edges())))
        logger.info("The subCFGs, subCDGs and subDDGs Analysis have been finished ...")

        # for addr in patched_block_addrs:
        #     print(addr)

        addr_to_cfgENode = {}
        inst_to_cfgENode_addr = {}
        idx_to_cfgENode_addr = {}
        cfgENode_addr_to_idx = {}
        func_to_addrs = []
        idx = 0
        for node in cfgE.graph.nodes():
            addr_to_cfgENode[node.addr] = node
            idx_to_cfgENode_addr[idx] = [node.addr]
            cfgENode_addr_to_idx[node.addr] = idx
            if cfgE.get_any_node(node.addr).function_address \
                    == patchedFunc.rebased_addr:
                func_to_addrs.append(node.addr)
            idx = idx + 1
            if node.block is not None:
                for inst_addr in node.block.instruction_addrs:
                    inst_to_cfgENode_addr[inst_addr] = node.addr

        cfgE_edges = set(())
        for src, dst in cfgE.graph.edges():
            cfgE_edges.add((src.addr, dst.addr))

        cdg_edges = set(())
        addr_to_cdg_predecessor_addrs = {}
        addr_to_cdg_successor_addrs = {}
        for src, dst in cdg.graph.edges():
            cdg_edges.add((src.addr, dst.addr))
            if dst.addr not in addr_to_cdg_predecessor_addrs:
                addr_to_cdg_predecessor_addrs[dst.addr] = []
            if src.addr not in addr_to_cdg_successor_addrs:
                addr_to_cdg_successor_addrs[src.addr] = []

            if src.addr not in addr_to_cdg_predecessor_addrs[dst.addr]:
                addr_to_cdg_predecessor_addrs[dst.addr].append(src.addr)
            if dst.addr not in addr_to_cdg_successor_addrs[src.addr]:
                addr_to_cdg_successor_addrs[src.addr].append(dst.addr)

        ddg_edges = set(())
        addr_to_ddg_predecessor_addrs = {}
        addr_to_ddg_successor_addrs = {}
        for src, dst in ddg.graph.edges():
            # print(src.ins_addr)
            if src.ins_addr in inst_to_cfgENode_addr \
                    and dst.ins_addr in inst_to_cfgENode_addr:
                src_node_addr = inst_to_cfgENode_addr[src.ins_addr]
                dst_node_addr = inst_to_cfgENode_addr[dst.ins_addr]
                ddg_edges.add((src_node_addr, dst_node_addr))

                if dst_node_addr not in addr_to_ddg_predecessor_addrs:
                    addr_to_ddg_predecessor_addrs[dst_node_addr] = []
                if src_node_addr not in addr_to_ddg_successor_addrs:
                    addr_to_ddg_successor_addrs[src_node_addr] = []

                if src_node_addr not in addr_to_ddg_predecessor_addrs[dst_node_addr]:
                    addr_to_ddg_predecessor_addrs[dst_node_addr].append(src_node_addr)
                if dst_node_addr not in addr_to_ddg_successor_addrs[src_node_addr]:
                    addr_to_ddg_successor_addrs[src_node_addr].append(dst_node_addr)

        sliced_patched_node_addrs = set(())
        iteration = 3
        sliced_node_addrs = patched_block_addrs

        # forward and backward slicing via control dependence
        while iteration > 0:
            new_cdg_sliced_node_addrs = []
            for addr in sliced_node_addrs:
                sliced_patched_node_addrs.add(addr)

                if addr in addr_to_cdg_predecessor_addrs:
                    for predecessor_addr in addr_to_cdg_predecessor_addrs[addr]:
                        if predecessor_addr not in sliced_patched_node_addrs \
                                and predecessor_addr in func_to_addrs:
                            new_cdg_sliced_node_addrs.append(predecessor_addr)
                            sliced_patched_node_addrs.add(predecessor_addr)

                if addr in addr_to_cdg_successor_addrs:
                    for successor_addr in addr_to_cdg_successor_addrs[addr]:
                        if successor_addr not in sliced_patched_node_addrs \
                                and successor_addr in func_to_addrs:
                            new_cdg_sliced_node_addrs.append(successor_addr)
                            sliced_patched_node_addrs.add(successor_addr)

                # for src, dst in cdg.graph.edges():
                #     # backward slicing via src control dependence edge
                #     if dst.addr == addr:
                #         sliced_patched_node_addrs.add(src.addr)
                #         if src.addr not in patched_block_addrs and src.addr not in sliced_patched_node_addrs:
                #             new_cdg_sliced_node_addrs.append(src.addr)
                #     # forward slicing via dst edge
                #     if src.addr == addr:
                #         sliced_patched_node_addrs.add(dst.addr)
                #         if dst.addr not in patched_block_addrs and dst.addr not in sliced_patched_node_addrs:
                #             new_cdg_sliced_node_addrs.append(dst.addr)

            sliced_node_addrs = new_cdg_sliced_node_addrs
            iteration = iteration - 1

        iteration = 3
        sliced_node_addrs = patched_block_addrs

        # forward and backward slicing via data dependence
        while iteration > 0:
            new_ddg_sliced_node_addrs = []
            for addr in sliced_node_addrs:
                sliced_patched_node_addrs.add(addr)

                if addr in addr_to_ddg_predecessor_addrs:
                    for predecessor_addr in addr_to_ddg_predecessor_addrs[addr]:
                        if predecessor_addr not in sliced_patched_node_addrs \
                                and predecessor_addr in func_to_addrs:
                            new_ddg_sliced_node_addrs.append(predecessor_addr)
                            sliced_patched_node_addrs.add(predecessor_addr)

                if addr in addr_to_ddg_successor_addrs:
                    for successor_addr in addr_to_ddg_successor_addrs[addr]:
                        if successor_addr not in sliced_patched_node_addrs \
                                and successor_addr in func_to_addrs:
                            new_ddg_sliced_node_addrs.append(successor_addr)
                            sliced_patched_node_addrs.add(successor_addr)

                # for src, dst in ddg.graph.edges():
                #     # print(src.ins_addr)
                #     src_node_addr = inst_to_cfgENode_addr[src.ins_addr]
                #     dst_node_addr = inst_to_cfgENode_addr[dst.ins_addr]
                #     # backward slicing via src data dependence edge
                #     if dst_node_addr == addr:
                #         sliced_patched_node_addrs.add(src_node_addr)
                #         if src_node_addr not in patched_block_addrs
                #         and src_node_addr not in sliced_patched_node_addrs:
                #             new_ddg_sliced_node_addrs.append(src_node_addr)
                #     # forward slicing via dst data dependence edge
                #     if src_node_addr == addr:
                #         sliced_patched_node_addrs.add(dst_node_addr)
                #         if dst_node_addr not in patched_block_addrs
                #         and dst_node_addr not in sliced_patched_node_addrs:
                #             new_ddg_sliced_node_addrs.append(dst_node_addr)
            sliced_node_addrs = new_ddg_sliced_node_addrs
            iteration = iteration - 1

        logger.info(patched_block_addrs)
        logger.info(sliced_patched_node_addrs)
        patch_related_nodes = []
        patched_cfg_edge_info = set(())
        patched_cdg_edge_info = set(())
        patched_ddg_edge_info = set(())

        for addr in sliced_patched_node_addrs:
            if addr_to_cfgENode[addr].block is not None:
                patch_related_nodes.append(addr_to_cfgENode[addr])
            for edge in cfgE_edges:
                if addr in edge:
                    # logger.info(edge)
                    # logger.info(edge[0])
                    # logger.info(edge[1])
                    # logger.info(cfgENode_addr_to_idx[edge[0]])
                    if addr_to_cfgENode[edge[0]].block is not None \
                            and addr_to_cfgENode[edge[1]].block is not None:
                        patched_cfg_edge_info.add((cfgENode_addr_to_idx[edge[0]],
                                                   cfgENode_addr_to_idx[edge[1]]))
                        patch_related_nodes.append(addr_to_cfgENode[edge[0]])
                        patch_related_nodes.append(addr_to_cfgENode[edge[1]])
            for edge in cdg_edges:
                if edge[0] in sliced_patched_node_addrs \
                        and edge[1] in sliced_patched_node_addrs:
                    if addr_to_cfgENode[edge[0]].block is not None \
                            and addr_to_cfgENode[edge[1]].block is not None:
                        patched_cdg_edge_info.add((cfgENode_addr_to_idx[edge[0]],
                                                   cfgENode_addr_to_idx[edge[1]]))
            for edge in ddg_edges:
                if edge[0] in sliced_patched_node_addrs \
                        and edge[1] in sliced_patched_node_addrs \
                        and edge[0] != edge[1]:
                    if addr_to_cfgENode[edge[0]].block is not None \
                            and addr_to_cfgENode[edge[1]].block is not None:
                        patched_ddg_edge_info.add((cfgENode_addr_to_idx[edge[0]],
                                                   cfgENode_addr_to_idx[edge[1]]))

        patch_related_nodes = list(set(patch_related_nodes))

        patched_funcs_to_slicing_info[patched_func] = []
        patched_nodes_to_insts = []
        patched_nodes_to_insts_detailed = []
        patched_nodes_idx = []
        for node in patch_related_nodes:
            if node.block is not None:
                patched_nodes_to_insts.append({"block_Idx": cfgENode_addr_to_idx[node.addr],
                                               "blockInsts": str(node.block.capstone.insns)})
                patched_nodes_idx.append(cfgENode_addr_to_idx[node.addr])
                insns_info = []
                for insn in node.block.capstone.insns:
                    insns_info.append("<" + str(insn.mnemonic) + "~~"
                                      + str(insn.op_str) + ">")
                patched_nodes_to_insts_detailed.append({"block_Idx": cfgENode_addr_to_idx[node.addr],
                                                        "blockInsts": insns_info})
        patched_funcs_to_slicing_info[patched_func]. \
            append({"patched_tag": patched_tag,
                    "cfg_block_info": patched_nodes_to_insts,
                    "cfg_block_detailed_info": patched_nodes_to_insts_detailed,
                    "cfg_edge_info": list(patched_cfg_edge_info),
                    "cdg_edge_info": list(patched_cdg_edge_info),
                    "ddg_edge_info": list(patched_ddg_edge_info)})
        logger.info(patched_nodes_idx)
        if patched_nodes_to_insts != [] and patched_cfg_edge_info != []:
            empty_flag = False
    gc.collect()
    end = datetime.datetime.now()
    logger.info("The execution time of patched slicing information "
                "extraction via angr: {}".format(str(end - start)))
    logger.info(patched_funcs_to_slicing_info)

    return patched_funcs_to_slicing_info, empty_flag


# Store the patched or unpatched assembly code snippets, CFG, CDG, DDG and slicing information
def patched_commit_patched_tag_handle(patched_tag, modify_index, patched_file,
                                      ir_binary_path, modified_funcs,
                                      patched_func_to_lines):
    logger.info('The patch information: {}---{}---{}'.
                format(patched_tag, ir_binary_path, patched_file))

    compilers = ["gcc", "clang"]
    optimizations = ["no", "O0", "O1", "O2", "O3", "Os"]

    success_flag = False

    for compiler in compilers:
        for optimization in optimizations:

            logger.info("The case of compiler {} with optimization {}.".format(compiler, optimization))
            patched_funcs_to_assembly_insts = {}
            patched_funcs_to_sub_graph = {}
            patched_funcs_to_patched_block_addrs = {}
            patched_funcs_to_slicing_info = {}

            cur_dir_path = ir_binary_path + "/" + compiler + "_" \
                           + patched_tag + "/" + optimization
            # patched_funcs_assembly_info_path = cur_dir_path
            # + "/" + patched_funcs_assembly_info
            binary_subgraph_success_info_path = cur_dir_path \
                                                + "/" + binary_subgraph_success_info
            # patched_funcs_binary_info_path = cur_dir_path
            # + "/" + patched_funcs_binary_info

            if os.path.exists(binary_subgraph_success_info_path):
                try:
                    success_temp = utility.file_to_object(binary_subgraph_success_info_path)
                    if "success_slicing_state" in success_temp:
                        # if success_temp["success_slicing_state"]:
                        logger.info("This program has been analyzed.")
                        continue
                except Exception as e:
                    logger.info(e)

            if patched_file.count("/") > 0:
                patched_source_file = patched_file[patched_file.rindex("/") + 1:]
                if patched_source_file.endswith(".c"):
                    logger.info("Patched source code file: " + patched_source_file)
                    patched_file_name = patched_source_file[:patched_source_file.rindex(".")]

                    if not os.path.exists(cur_dir_path):
                        logger.info(cur_dir_path + ": directory not exists.")
                        continue
                    os.chdir(cur_dir_path)

                    for func_info in modified_funcs[modify_index]:
                        logger.info("Patched function: {}---{} ".format(modify_index, func_info["function"]))

                        # The string parse of function name
                        func_name = func_info["function"]
                        if func_name.count(" ") > 0:
                            func_name = func_name[func_name.rindex(" ") + 1:]
                        if func_name.count("*") > 0:
                            func_name = func_name[func_name.index("*") + 1:]

                        patched_funcs_to_assembly_insts[func_name] = []
                        patched_lines_info = patched_func_to_lines[func_name]

                        assembly_file = cur_dir_path + "/" + patched_file_name + ".s"  # _intel.s
                        if compiler == "gcc":
                            assembly_file = cur_dir_path + "/" + patched_file_name + "_gcc.s"
                        logger.info(assembly_file)

                        # Extract each patched function information from assembly files via debug information
                        if os.path.exists(assembly_file):
                            try:
                                patched_funcs_to_assembly_insts[func_name], assembly_empty_flag \
                                    = extract_patched_assembly_code_from_debug_file(assembly_file, func_name,
                                                                                    patched_lines_info,
                                                                                    patched_tag)
                                if assembly_empty_flag:
                                    logger.info("Empty patched instructions for patched function: "
                                                "{} from assembly files.".format(func_name))
                                else:
                                    success_flag = True

                            except Exception as e:
                                logger.info("Assembly file error information: " + str(e))
                                logger.info(traceback.format_exc())
                        else:
                            logger.info("Assembly file does not exist.")

                    # Extract all patched function information from binary files via disassembly tools
                    binary_file = cur_dir_path + "/" + patched_file_name + ".o"
                    logger.info(binary_file)
                    if os.path.exists(binary_file):
                        try:
                            if patched_tag == "after":
                                logger.info("Patched information:")
                            else:
                                logger.info("Unpatched information:")
                            patched_funcs_to_sub_graph, binary_empty_flag, patched_funcs_to_patched_block_addrs = \
                                extract_patched_assembly_code_from_binary_file_angr(binary_file,
                                                                                    patched_funcs_to_assembly_insts,
                                                                                    patched_tag)
                            if binary_empty_flag:
                                logger.info(
                                    "Empty patched sub graph information from binary file: {}.".format(binary_file))

                            logger.info(patched_funcs_to_sub_graph)
                            logger.info(patched_funcs_to_patched_block_addrs)

                            patched_funcs_to_slicing_info, binary_slicing_empty_flag = \
                                extract_patched_assembly_code_from_binary_file_angr2(binary_file,
                                                                                     patched_funcs_to_patched_block_addrs,
                                                                                     patched_tag)
                            if binary_slicing_empty_flag:
                                logger.info(
                                    "Empty patched slicing information from binary file: {}.".format(binary_file))
                        except Exception as e:
                            logger.info("Binary file error information: " + str(e))
                            logger.info(traceback.format_exc())
                    else:
                        logger.info("Binary file does not exist.")

            logger.info(patched_funcs_to_assembly_insts)
            utility.object_to_file(cur_dir_path + "/" +
                                   patched_funcs_assembly_info,
                                   patched_funcs_to_assembly_insts)

            success_info = {"success_slicing_state": success_flag}
            utility.object_to_file(binary_subgraph_success_info_path, success_info)

            # {"patched_tag":"", "cfg_block_info":"", "cfg_edge_info":""}
            # print(patched_funcs_to_sub_graph)
            # The storage of patched subgraph
            if success_flag:
                for func, info in patched_funcs_to_sub_graph.items():
                    utility.object_to_file(cur_dir_path + "/patched_func_subgraph_info++"
                                           + func, info)
                for func, info in patched_funcs_to_slicing_info.items():
                    utility.object_to_file(cur_dir_path + "/patched_func_slicing_info++"
                                           + func, info)
            # logger.info(patched_funcs_to_sub_graph)
            # object_to_file(cur_dir_path + "/" + patched_funcs_binary_info, patched_funcs_to_sub_graph)
    return {}


# generate and extract patched information
def patched_commit_handle(modified_files, ir_binary_path,
                          modified_funcs,
                          patched_func_to_lines):
    # if len(modified_files) > 1:
    #     logger.info("Currently, we only handle modifications in one patched source code file.")
    #     return
    for modify_idx in modified_files:
        after_patched_files = modified_files[modify_idx]["after"]
        patched_commit_patched_tag_handle("after", modify_idx,
                                          after_patched_files,
                                          ir_binary_path,
                                          modified_funcs,
                                          patched_func_to_lines)

        before_patched_files = modified_files[modify_idx]["before"]
        patched_commit_patched_tag_handle("before", modify_idx,
                                          before_patched_files,
                                          ir_binary_path,
                                          modified_funcs,
                                          patched_func_to_lines)


def main(divided_commits_dir):
    vuln_Idx = 0
    print(divided_commits_dir)
    for filename in os.listdir(divided_commits_dir):
        commit_path = divided_commits_dir + "/" + filename
        # logger.info(commit_path)
        if os.path.isfile(commit_path):
            # if filename.count('.') >= 4:
            if filename.count('.') >= 2:

                info = filename.split('.')
                vuln_id = info[0]

                # for security patch dataset
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]
                # vuln_commit_hash = info[3]

                # for judged security patch dataset
                vuln_software_project = info[0]
                vuln_software_dir = info[1]
                vuln_commit_hash = info[2]

                # if vuln_commit_hash != "fc76936d3ea5720a6e0948a08381b803a68deb28":
                #     continue

                # timeout when constructing CFG
                if vuln_commit_hash in timeout_commits:
                    continue

                # for non security patch dataset
                # vuln_commit_hash = info[0]
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]

                # if vuln_id != "CVE-2015-9289":
                #     continue
                # if vuln_software_dir != "linux":
                #     continue
                # if vuln_software_project != "torvalds":
                #     continue
                # if vuln_software_project not in built_projects:
                #     continue

                vuln_Idx = vuln_Idx + 1
                logger.info("The analysis of " + str(vuln_Idx) + " vulnerability: " + vuln_id + ".")

                commit_ir_binary_dir = divided_commits_dir + "/" + filename[:filename.rindex(".")] \
                                       + "/" + vuln_commit_hash
                if not os.path.exists(commit_ir_binary_dir):
                    continue
                patch_meta_path = commit_ir_binary_dir + "/" + patch_meta
                if not os.path.exists(patch_meta_path):
                    continue

                logger.info(patch_meta_path)
                modified_files, modified_funcs, patched_func_to_file_Idx, patched_func_to_lines = \
                    patched_source_code_lines_extract(patch_meta_path)

                logger.info(modified_files)
                logger.info(modified_funcs)

                patched_commit_handle(modified_files, commit_ir_binary_dir,
                                      modified_funcs, patched_func_to_lines)
                # break
                utility.terminal_clear()


if __name__ == '__main__':
    divided_commits_dir = commits_dir + "/" + sys.argv[1]
    print("test1: ", divided_commits_dir)
    main(divided_commits_dir)
