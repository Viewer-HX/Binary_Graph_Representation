'''
    This script converts the stored patched and unpatched subgraph into
    formatting output
'''



import os
import logging
from utility import file_to_object, get_subfiles_with_prefix_from_dir
from traceback import format_exc

built_projects = ["openssl", "libav"]

# Convert the patched sub graphs into formatting output
def patched_commit_sub_graph_format_handle(commit_hash, ir_binary_path):
    global logger
    global sub_graph_format_dir

    patched_subgraph_prefix = "patched_func_subgraph_info++"
    binary_subgraph_success_info = "patch_subgraph_success"
    subgraph_success_tag = "success_state"


    logger.info('Patched information:{}---{}'.format(commit_hash, ir_binary_path))
    compilers = ["gcc", "clang"]
    optimizations = ["no", "O0", "O1", "O2", "O3", "Os"]  # ["default", "no", "O0", "O1", "O2", "O3", "Os"]

    for compiler in compilers:
        for optimization in optimizations:

            cur_dir_path = ir_binary_path + "/" + compiler + "_after/" + optimization
            cur_dir_before_path = ir_binary_path + "/" + compiler + "_before/" + optimization

            binary_subgraph_success_info_path = cur_dir_path + "/" + binary_subgraph_success_info

            if os.path.exists(binary_subgraph_success_info_path):
                try:
                    success_temp = file_to_object(binary_subgraph_success_info_path)
                    if success_temp[subgraph_success_tag]:
                        print("test2")
                        patched_funcs_file = get_subfiles_with_prefix_from_dir(cur_dir_path,
                                                                                       patched_subgraph_prefix)
                        for patched_func_file in patched_funcs_file:

                            patched_func_path = cur_dir_path + "/" + patched_func_file
                            unpatched_func_path = cur_dir_before_path + "/" + patched_func_file

                            patched_func_name = patched_func_file.replace(patched_subgraph_prefix, "")
                            # print(commit_hash)
                            sub_graph_output_file = sub_graph_format_dir + "/" + commit_hash \
                                                    + "-" + compiler + "-" + optimization \
                                                    + "-" + patched_func_name
                            # print(sub_graph_output_file)
                            output_file = open(sub_graph_output_file, 'w')

                            # {"patched_tag":"", "cfg_block_info": {"block_Idx": "", "blockInsts": ""},
                            # "cfg_edge_info": "list(set(()))"}
                            patched_func_info = {}
                            unpatched_func_info = {}

                            # print(patched_func_path)
                            # print(unpatched_func_path)
                            # print(os.path.exists(patched_func_path))
                            # print(os.path.exists(unpatched_func_path))

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

                            # formatting output the sub graph edge information
                            for unpatched_func_info_each in unpatched_func_info:
                                # print(len(unpatched_func_info["cfg_edge_info"]))
                                if len(unpatched_func_info_each["cfg_edge_info"]) > 0:
                                    # print("++++++++++++++++unpatched edge information+++++++++")
                                    # print(unpatched_func_info_each["cfg_edge_info"])
                                    for edge in unpatched_func_info_each["cfg_edge_info"]:
                                        output_file.write("(" + str(edge[0]) + ","
                                                          + str(edge[1]) + ",0)\n")
                            for patched_func_info_each in patched_func_info:
                                if len(patched_func_info_each["cfg_edge_info"]) > 0:
                                    # print("++++++++++++++++patched edge information+++++++++")
                                    # print(patched_func_info_each["cfg_edge_info"])
                                    for edge in patched_func_info_each["cfg_edge_info"]:
                                        output_file.write("(" + str(edge[0]) + ","
                                                          + str(edge[1]) + ",1)\n")

                            output_file.write("===========================\n")

                            # formatting output the sub graph node information
                            for unpatched_func_info_each in unpatched_func_info:
                                if len(unpatched_func_info_each["cfg_block_info"]) > 0:
                                    # print("++++++++++++++++unpatched block information+++++++++")
                                    # print(unpatched_func_info_each["cfg_block_info"])
                                    for block in unpatched_func_info_each["cfg_block_info"]:
                                        # print(block["blockInsts"])
                                        insts_str = ""
                                        block_insts = block["blockInsts"][1:len(block["blockInsts"])-1]
                                        insts = block_insts.split(",")
                                        for inst in insts:
                                            insts_str = insts_str + "," + inst[inst.index('"')+1:inst.rindex('"')]
                                        output_file.write("(" + str(block["block_Idx"]) + ","
                                                          + insts_str[1:] + ",0)\n")

                            for patched_func_info_each in patched_func_info:
                                if len(patched_func_info_each["cfg_block_info"]) > 0:
                                    # print("++++++++++++++++patched block information+++++++++")
                                    for block in patched_func_info_each["cfg_block_info"]:
                                        insts_str = ""
                                        block_insts = block["blockInsts"][1:len(block["blockInsts"]) - 1]
                                        insts = block_insts.split(",")
                                        for inst in insts:
                                            insts_str = insts_str + "," + inst[inst.index('"')+1:inst.rindex('"')]
                                        output_file.write("(" + str(block["block_Idx"]) + ","
                                                          + insts_str[1:] + ",1)\n")
                            output_file.close()
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
                # logger.info("The analysis of " + str(vuln_Idx) + " vulnerability: "
                #             + vuln_id + ".")
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
                # if vuln_software_dir != "linux":
                #     continue
                # if vuln_software_project != "torvalds":
                #     continue
                if vuln_software_project not in built_projects:
                    continue
                # print("test1")
                commit_ir_binary_dir = commits_dir + "/" + filename[:filename.rindex(".")] \
                                       + "/" + vuln_commit_hash
                if not os.path.exists(commit_ir_binary_dir):
                    continue
                patch_meta_path = commit_ir_binary_dir + "/" + patch_meta
                if not os.path.exists(patch_meta_path):
                    continue
                print("test1: ", commit_ir_binary_dir)
                logger.info(patch_meta_path)
                patched_commit_sub_graph_format_handle(vuln_commit_hash, commit_ir_binary_dir)
                # break
                # terminal_clear()


if __name__ == '__main__':

    # Record in different log files
    log_file_name = "patched-subgraph-security-info.log"
    idx = 0
    while os.path.exists("Log/" + log_file_name + str(idx)):
        idx = idx + 1
    log_file_name = log_file_name + str(idx)
    logger = logging.getLogger('log')
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("Log/" + log_file_name, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    sub_graph_format_dir = "/home/xu/SoftwarePatch/judged/negatives/ProjectOpenssl/graph/cfgformat"
    security_commits_dir = "/home/xu/SoftwarePatch/judged/negatives/ProjectOpenssl"
    # security_split_num = 6
    # for security patch dataset
    # for num in range(1, security_split_num):
    #     commits_dir = security_commits_dir + "_" + str(num)
    #     main(commits_dir)
    main(security_commits_dir)
    # sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/security_judged_subgraph_format_output"
    # sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/nonSecurity_subgraph_format_output"
    # non_security_commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/negatives_kernel_v2"
    # non_security_split_num = 10
    # # for non security patch dataset
    # for num in range(1, non_security_split_num):
    #     commits_dir = non_security_commits_dir + "_" + str(num)
    #     main(commits_dir)
    #
    # security_judegd_commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/positives_kernel_v1"
    # security_judegd_split_num = 10
    # # for judged security patch dataset
    # for num in range(1, security_judegd_split_num):
    #     commits_dir = security_judegd_commits_dir + "_" + str(num)
    #     main(commits_dir)