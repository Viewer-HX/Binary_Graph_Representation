'''
    This script extracts numerical attribute of each assembly block;
'''



import os
import logging
from utility import file_to_object, get_subfiles_with_prefix_from_dir
# from datetime import datetime
from traceback import format_exc
# from func_timeout import FunctionTimedOut, func_set_timeout
# from angr import Project, sim_options
import numpy as np


# log_things = ["angr", "pyvex", "claripy", "cle"]
# for log in log_things:
#     logger = logging.getLogger(log)
#     logger.disabled = True
#     logger.propagate = False

# Judge whether the opcode belong to specific category
def opcode_in_category(opcode, insts_category):
    for inst in insts_category:
        if opcode.startswith(inst):
            return True
    return False


# Judge whether the operand is string consts
def is_string_consts(operand, offsetStrMapping):
    opstrNum = ""
    if operand.startswith("0x") or operand.startswith("0X"):
        opstrNum = str(int(operand, 16))
    if opstrNum in offsetStrMapping:
        return True
    return False


# Count the numerical attributes of assembly blocks
# No. of numeric constants
# No. of transfer instructions
# No. of calls
# No. instructions
# No. arithmetic instructions
def count_num_attr(block_insts):
    arithmetic_instructions = ['inc', 'dec', 'add', 'sub',
                               'mul', 'imul', 'div', 'idiv'
                               'neg', 'adc', 'sbb']
    transfer_instructions = ['mov', 'push', 'pop', 'xchg',
                             'lahf', 'sahf', 'in', 'out',
                             'lds', 'les', 'lea']

    num_numeric_const_insts = 0
    num_trans_insts = 0
    num_calls = 0
    num_arith_insts = 0


    for inst in block_insts:
        # print(inst)
        inst_info = inst[1:-1].split("~~")
        opcode = inst_info[0].strip()
        # print(opcode)
        operands = inst_info[1]
        if ',' in operands:
            for operand in operands.split(","):
                operand = operand.strip()
                # print(operand)
                if operand.startswith("0x") \
                        or operand.startswith("-0x") \
                        or operand.replace('.', '', 1).replace('-', '', 1).isdigit():
                    num_numeric_const_insts = \
                        num_numeric_const_insts + 1
        else:
            operand = operands.strip()
            if operand.startswith("0x") \
                    or operand.startswith("-0x") \
                    or operand.replace('.', '', 1).replace('-', '', 1).isdigit():
                num_numeric_const_insts = \
                    num_numeric_const_insts + 1

        if opcode_in_category(opcode, transfer_instructions):
            num_trans_insts = num_trans_insts + 1
        if opcode.startswith("call"):
            num_calls = num_calls + 1
        if opcode_in_category(opcode, arithmetic_instructions):
            num_arith_insts = num_arith_insts + 1
        # print("===============")
    num_attr = [num_numeric_const_insts, num_trans_insts,
                num_calls, len(block_insts), num_arith_insts]
    # print(num_attr)
    return num_attr


# Count the numerical attributes of assembly blocks
# No. of numeric constants
# No. of string constants
# No. of transfer instructions
# No. of calls
# No. instructions
# No. arithmetic instructions
def count_num_attr2(block_insts, offsetStrMap):
    arithmetic_instructions = ['inc', 'dec', 'add', 'sub',
                               'mul', 'imul', 'div', 'idiv'
                               'neg', 'adc', 'sbb']
    transfer_instructions = ['mov', 'push', 'pop', 'xchg',
                             'lahf', 'sahf', 'in', 'out',
                             'lds', 'les', 'lea']

    num_numeric_const_insts = 0
    num_string_const_insts = 0
    num_trans_insts = 0
    num_calls = 0
    num_arith_insts = 0


    for inst in block_insts:
        # print(inst)
        inst_info = inst[1:-1].split("~~")
        opcode = inst_info[0].strip()
        # print(opcode)
        operands = inst_info[1]
        if ',' in operands:
            for operand in operands.split(","):
                operand = operand.strip()
                # print(operand)
                if operand.startswith("0x") \
                        or operand.startswith("-0x") \
                        or operand.replace('.', '', 1).replace('-', '', 1).isdigit():
                    num_numeric_const_insts = \
                        num_numeric_const_insts + 1
                if is_string_consts(operand, offsetStrMap):
                    num_string_const_insts = num_string_const_insts + 1
        else:
            operand = operands.strip()
            if operand.startswith("0x") \
                    or operand.startswith("-0x") \
                    or operand.replace('.', '', 1).replace('-', '', 1).isdigit():
                num_numeric_const_insts = \
                    num_numeric_const_insts + 1
            if is_string_consts(operand, offsetStrMap):
                num_string_const_insts = num_string_const_insts + 1

        if opcode_in_category(opcode, transfer_instructions):
            num_trans_insts = num_trans_insts + 1
        if opcode.startswith("call"):
            num_calls = num_calls + 1
        if opcode_in_category(opcode, arithmetic_instructions):
            num_arith_insts = num_arith_insts + 1
        # print("===============")
    num_attr = [num_numeric_const_insts, num_string_const_insts,
                num_trans_insts, num_calls, len(block_insts), num_arith_insts]
    # print(num_attr)
    return num_attr


# @func_set_timeout(10 * 60)
# # Perform cfg task
# def cfg_task(prog, patchedFunc):
#     cfg = prog.analyses.CFGFast(function_starts=[patchedFunc.rebased_addr])
#     return cfg


# count string constants
def offsetStrMappingGen(cfg, binary):
    offsetStrMapping = {}
    for func in cfg.functions.values():
        if func.binary_name == binary:
            for offset, strRef in func.string_references(vex_only=True):
                offset = str(offset)
                #offset = str(hex(offset))[:-1]
                if offset not in offsetStrMapping:
                    offsetStrMapping[offset] = ''.join(strRef.split())
    return offsetStrMapping

# Extract meta information of patch from "patch_info.txt"
def patched_source_code_lines_extract(patch_meta_path):
    patched_func_to_lines = {}
    patched_func_to_file_Idx = {}

    patched_info = file_to_object(patch_meta_path)
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



# Convert the patched sub graphs into formatting output
def patched_commit_sub_graph_format_handle(commit_hash, ir_binary_path,
                                           patched_func_to_file_Idx, modified_files):
    global logger
    global sub_graph_format_dir
    global numerical_attribute_dir
    global block_num

    patched_subgraph_prefix = "patched_func_subgraph_info++"
    binary_subgraph_success_info = "subgraph_state"
    subgraph_success_tag = "subcfg_state"


    logger.info('Patched information:{}---{}'.format(commit_hash, ir_binary_path))
    compilers = ["gcc", "clang"]
    optimizations = ["no", "O0", "O1", "O2", "O3", "Os"]

    for compiler in compilers:
        for optimization in optimizations:

            cur_dir_path = ir_binary_path + "/" + compiler + "_after/" + optimization
            cur_dir_before_path = ir_binary_path + "/" + compiler + "_before/" + optimization

            binary_subgraph_success_info_path = cur_dir_path + "/" + binary_subgraph_success_info

            if not os.path.exists(binary_subgraph_success_info_path):
                continue
            try:
                success_temp = file_to_object(binary_subgraph_success_info_path)
                if success_temp[subgraph_success_tag]:

                    patched_funcs_file = get_subfiles_with_prefix_from_dir(
                        cur_dir_path,
                        patched_subgraph_prefix)
                    for patched_func_file in patched_funcs_file:

                        patched_func_path = cur_dir_path + "/" + patched_func_file
                        unpatched_func_path = cur_dir_before_path + "/" + patched_func_file

                        patched_func_name = patched_func_file.replace(patched_subgraph_prefix, "")

                        patched_file_idx = patched_func_to_file_Idx[patched_func_name]
                        patched_file = modified_files[patched_file_idx]["after"]
                        patched_file_name = patched_file[patched_file.rindex("/")
                                                         + 1:patched_file.rindex(".")]
                        patched_binary_file = cur_dir_path + "/" + patched_file_name + ".o"
                        unpatched_binary_file = cur_dir_before_path + "/" + patched_file_name + ".o"


                        # {"patched_tag":"", "cfg_block_info": {"block_Idx": "", "blockInsts": ""},
                        # "cfg_edge_info": "list(set(()))"}
                        patched_func_info = {}
                        unpatched_func_info = {}

                        if os.path.exists(patched_func_path):
                            # print("+++++++++++++after patch++++++++++++")
                            patched_func_info = file_to_object(patched_func_path)
                            # print(patched_func_info)
                        if os.path.exists(unpatched_func_path):
                            # print("+++++++++before patch+++++++++")
                            unpatched_func_info = file_to_object(unpatched_func_path)
                            # print(unpatched_func_info)
                        # print(patched_func_info)
                        # print(unpatched_func_info)

                        try:
                            # The below is the procession of unpatched program
                            # unpatched_prog = Project(unpatched_binary_file,
                            #                          load_options={'auto_load_libs': False})
                            # get_symbol = unpatched_prog.loader.main_object.get_symbol
                            # unpatchedFunc = get_symbol(patched_func_name)
                            #
                            # logger.info("Analyzing the binaries to generate subCFGs from patched function ...")
                            # unpatched_cfg = {}
                            # start_cfg_fast = datetime.now()
                            # try:
                            #     unpatched_cfg = cfg_task(unpatched_prog, unpatchedFunc)
                            # except FunctionTimedOut:
                            #     logger.info(
                            #         "The construction of CFG can not complete in 10 minutes and was terminated.")
                            # end_cfg_fast = datetime.now()
                            # logger.info("The execution time of CFG Fast: {}".
                            #             format(str(end_cfg_fast - start_cfg_fast)))
                            # if unpatched_cfg == {}:
                            #     continue
                            # logger.info("It has %d nodes and %d edges in CFGFast" %
                            #             (len(unpatched_cfg.graph.nodes()), len(unpatched_cfg.graph.edges())))
                            #
                            # unpatched_offsetStrMap = offsetStrMappingGen(unpatched_cfg, patched_file_name + ".o")
                            # logger.info(unpatched_offsetStrMap)

                            unpatched_edges_to_childs = {}

                            # formatting output the sub graph edge information
                            for unpatched_func_info_each in unpatched_func_info:
                                if len(unpatched_func_info_each["cfg_edge_info"]) > 0:
                                    # print("++++++++++++++++unpatched edge information+++++++++")
                                    # print(unpatched_func_info_each["cfg_edge_info"])
                                    for edge in unpatched_func_info_each["cfg_edge_info"]:
                                        # print("(" + str(edge[0]) + ","
                                        #  + str(edge[1]) + ")")
                                        src = str(edge[0])
                                        if src not in unpatched_edges_to_childs:
                                            unpatched_edges_to_childs[src] = 0
                                        temp = unpatched_edges_to_childs[src]
                                        temp = temp + 1
                                        unpatched_edges_to_childs[src] = temp
                            # print(unpatched_edges_to_childs)

                            # formatting output the sub graph node information
                            for unpatched_func_info_each in unpatched_func_info:
                                if "cfg_block_detailed_info" in unpatched_func_info_each and \
                                        len(unpatched_func_info_each["cfg_block_detailed_info"]) > 0:
                                    # print("++++++++++++++++unpatched block information+++++++++")
                                    # print(unpatched_func_info_each["cfg_block_info"])
                                    for block in unpatched_func_info_each["cfg_block_detailed_info"]:
                                        # print(block["blockInsts"])
                                        b_idx = str(block["block_Idx"])
                                        # print(block['block_Idx'])
                                        block_insts = block["blockInsts"]
                                        sub_graph_block_num_attr = numerical_attribute_dir + "/" + commit_hash \
                                                                   + "-" + compiler + "-" + optimization \
                                                                   + "-" + patched_func_name + "-before-block-" \
                                                                   + b_idx + ".npy"
                                        block_num_attr = count_num_attr(block_insts)
                                        # print(block_num_attr)
                                        # print(unpatched_edges_to_childs[b_idx])
                                        block_num = block_num + 1
                                        # print("The {}th block: ".format(str(block_num)))
                                        if b_idx in unpatched_edges_to_childs:
                                            block_num_attr.append(int(unpatched_edges_to_childs[b_idx]))
                                        else:
                                            block_num_attr.append(0)
                                        block_num_attr = np.array(block_num_attr)
                                        # print(block_num_attr)
                                        np.save(sub_graph_block_num_attr, block_num_attr)
                                        # num_attr = np.load(sub_graph_block_num_attr)
                                        # print(num_attr)
                        except Exception as e:
                            logger.info(e)

                        try:
                            # The below is the procession of patched program

                            # patched_prog = Project(patched_binary_file,
                            #                        load_options={'auto_load_libs': False})
                            # get_symbol = patched_prog.loader.main_object.get_symbol
                            # patchedFunc = get_symbol(patched_func_name)
                            # logger.info("Analyzing the binaries to generate subCFGs from patched function ...")
                            # patched_cfg = {}
                            # start_cfg_fast = datetime.now()
                            # try:
                            #     patched_cfg = cfg_task(patched_prog, patchedFunc)
                            # except FunctionTimedOut:
                            #     logger.info(
                            #         "The construction of CFG can not complete in 10 minutes and was terminated.")
                            # end_cfg_fast = datetime.now()
                            # logger.info("The execution time of CFG Fast: {}".
                            #             format(str(end_cfg_fast - start_cfg_fast)))
                            # if patched_cfg == {}:
                            #     continue
                            # logger.info("It has %d nodes and %d edges in CFGFast" %
                            #             (len(patched_cfg.graph.nodes()), len(patched_cfg.graph.edges())))
                            #
                            # patched_offsetStrMap = offsetStrMappingGen(patched_cfg, patched_file_name + ".o")
                            # logger.info(patched_offsetStrMap)

                            patched_edges_to_childs = {}

                            # formatting output the sub graph edge information
                            for patched_func_info_each in patched_func_info:
                                if len(patched_func_info_each["cfg_edge_info"]) > 0:
                                    # print("++++++++++++++++unpatched edge information+++++++++")
                                    # print(unpatched_func_info_each["cfg_edge_info"])
                                    for edge in patched_func_info_each["cfg_edge_info"]:
                                        # print("(" + str(edge[0]) + ","
                                        #       + str(edge[1]) + ")")
                                        src = str(edge[0])
                                        if src not in patched_edges_to_childs:
                                            patched_edges_to_childs[src] = 0
                                        temp = patched_edges_to_childs[src]
                                        temp = temp + 1
                                        patched_edges_to_childs[src] = temp
                            # print(patched_edges_to_childs)

                            for patched_func_info_each in patched_func_info:
                                if "cfg_block_detailed_info" in patched_func_info_each and \
                                        len(patched_func_info_each["cfg_block_detailed_info"]) > 0:
                                    # print("++++++++++++++++patched block information+++++++++")
                                    for block in patched_func_info_each["cfg_block_detailed_info"]:
                                        b_idx = str(block["block_Idx"])
                                        # print(block["blockInsts"])
                                        # print(block['block_Idx'])
                                        block_insts = block["blockInsts"]
                                        sub_graph_block_num_attr = numerical_attribute_dir + "/" + commit_hash \
                                                                   + "-" + compiler + "-" + optimization \
                                                                   + "-" + patched_func_name + "-after-block-" \
                                                                   + b_idx + ".npy"
                                        block_num_attr = count_num_attr(block_insts)
                                        block_num = block_num + 1
                                        # print("The {}th block: ".format(str(block_num)))
                                        # print(block_num_attr)
                                        # print(patched_edges_to_childs[b_idx])
                                        if b_idx in patched_edges_to_childs:
                                            block_num_attr.append(int(patched_edges_to_childs[b_idx]))
                                        else:
                                            block_num_attr.append(0)
                                        block_num_attr = np.array(block_num_attr)
                                        # print(block_num_attr)
                                        np.save(sub_graph_block_num_attr, block_num_attr)
                                        # num_attr = np.load(sub_graph_block_num_attr)
                                        # print(num_attr)
                        except Exception as e:
                            logger.info(e)
            except Exception as e:
                logger.info(e)
                logger.info(format_exc())


def main(commits_dir):
    global logger

    patch_meta = "patch_info.txt"
    vuln_Idx = 0

    for filename in os.listdir(commits_dir):
        commit_path = commits_dir + "/" + filename
        logger.info(commit_path)
        if os.path.isfile(commit_path):
            # if filename.count('.') >= 4:
            if filename.count('.') >= 2:

                vuln_Idx = vuln_Idx + 1
                info = filename.split('.')

                # vuln_id = info[0]
                # # logger.info("The analysis of " + str(vuln_Idx) + " vulnerability: "
                # #             + vuln_id + ".")
                # # for security patch dataset
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]
                # vuln_commit_hash = info[3]

                # for non security patch dataset
                # vuln_commit_hash = info[0]
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]

                # for judged security patch dataset
                vuln_software_project = info[0]
                vuln_software_dir = info[1]
                vuln_commit_hash = info[2]

                # if vuln_id != "CVE-2018-10938":
                #     continue
                if vuln_software_dir != "linux":
                    continue
                if vuln_software_project != "torvalds":
                    continue
                commit_ir_binary_dir = commits_dir + "/" + filename[:filename.rindex(".")] \
                                       + "/" + vuln_commit_hash
                if not os.path.exists(commit_ir_binary_dir):
                    continue
                patch_meta_path = commit_ir_binary_dir + "/" + patch_meta
                if not os.path.exists(patch_meta_path):
                    continue
                modified_files, modified_funcs, patched_func_to_file_Idx, patched_func_to_lines = \
                patched_source_code_lines_extract(patch_meta_path)

                logger.info(patch_meta_path)
                patched_commit_sub_graph_format_handle(vuln_commit_hash, commit_ir_binary_dir,
                                                       patched_func_to_file_Idx, modified_files)
                # break
                # terminal_clear()


if __name__ == '__main__':

    # Record in different log files
    log_file_name = "patched-judged-num-attr-info.log"
    idx = 0
    while os.path.exists("Log/" + log_file_name + str(idx)):
        idx = idx + 1
    log_file_name = log_file_name + str(idx)
    logger = logging.getLogger('log')
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("Log/" + log_file_name, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    block_num = 0

    security_judegd_commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/positives_kernel_v1"
    sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                           "subgraph/security_judged_subgraph_format_output"
    numerical_attribute_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                              "block_num_attr/security_judged_block_num_attr"

    security_judegd_split_num = 10
    # for judged security patch dataset
    for num in range(1, security_judegd_split_num):
        commits_dir = security_judegd_commits_dir + "_" + str(num)
        main(commits_dir)

    print("Total block detailed number: {} in Security judged patches.".format(block_num))
    block_num = 0

    sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                           "subgraph/nonSecurity_subgraph_format_output"
    non_security_commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/negatives_kernel_v2"

    numerical_attribute_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                              "block_num_attr/nonSecurity_judged_block_num_attr"
    non_security_split_num = 10
    # for non security patch dataset
    for num in range(1, non_security_split_num):
        commits_dir = non_security_commits_dir + "_" + str(num)
        main(commits_dir)
    print("Total block detailed number: {} in nonSecurity judged patches.".format(block_num))

