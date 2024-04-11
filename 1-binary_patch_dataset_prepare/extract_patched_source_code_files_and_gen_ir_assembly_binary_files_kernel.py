
'''
    This script provides the following functions:
    1) extracts patched and unpatched source code files from patch related commit message;
    2) compiles the source code files into LLVM IR files, assembly files and binary files
    via gcc and clang with different optimization levels;
    3) for github kernel repository.
'''

import os
import shutil
import logging
import utility
import github_commit_operations
import software_build_dependence_operation

from goto import with_goto


# The absolute path of patch related commit message dataset
# commits_dir = "/home/binaryf/Binary_database/SecretPatch/SecurityDataset"
# commits_dir = "/home/binaryf/Binary_database/SecretPatch/nonSecurityDatasetv1"
commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/positives"
# commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/negatives"
# commits_dir = "/home/binaryf/Binary_database/Crawler/KernelSecurityDataset"
# commits_dir = "/home/binaryf/Binary_database/Crawler/KernelSecurityDatasetx86v4"

temp_dir = "temp"
empty_project_list = ["openbsd-libssl", "appweb", "goahead" ] # non exists project , "goahead"
compiler_option_dir = "compileOption"

linux_clang_compiler_cmds_dir = "/home/binaryf/Binary_database/Kernel_compiler_cmd/clang"
linux_gcc_compiler_cmds_dir = "/home/binaryf/Binary_database/Kernel_compiler_cmd/gcc"
linux_all_commits_stat_info_filepath = "/home/binaryf/Binary_database/Kernel/Stat/linux_all_commits_stat_info.json"
kernel_optimization_levels = ["O0", "O1", "O2", "O3", "Os"]
# kernel_platforms = ["alpha", "arc", "arm", "arm64",
# "c6x", "csky", "h8300", "hexagon", "ia64", "m68k",
# "microblaze", "mips", "nds32", "nios2", "openrisc",
# "parisc", "powerpc", "riscv", "s390", "sh", "sparc",
# "um", "unicore32", "x86", "xtensa"]

# Record in different log files
log_file_name = "patchedSourceCodeFilesAndIRFiles-Extraction-Process-Info.log"
idx = 0
while os.path.exists("Log/"+ log_file_name+ str(idx)):
    idx = idx + 1
log_file_name = log_file_name + str(idx)
logging.basicConfig(level=logging.DEBUG,
                    filename="Log/"+ log_file_name,
                    filemode='w')


# Get correct IR or gcc assembly compiler cmds for source code file <file_name>
def get_compiler_cmd(file_name, cur_commit_hash_ver, linux_all_compiler_cmds):

    sorted_kernel_versions = ["v2.6.12", "v2.6.13", "v2.6.16", "v2.6.17", "v2.6.19", "v2.6.20", "v2.6.21", "v2.6.22",
                              "v2.6.23", "v2.6.24", "v2.6.25", "v2.6.26", "v2.6.27", "v2.6.28", "v2.6.29", "v2.6.30",
                              "v2.6.31", "v2.6.32", "v2.6.33", "v2.6.34", "v2.6.35", "v2.6.36", "v2.6.37", "v2.6.38",
                              "v2.6.39", "v3.0", "v3.1", "v3.2", "v3.3", "v3.4", "v3.5", "v3.6", "v3.7", "v3.8", "v3.9",
                              "v3.10", "v3.11", "v3.12", "v3.13", "v3.14", "v3.15", "v3.16", "v3.17", "v3.18", "v3.19",
                              "v4.0", "v4.1", "v4.2", "v4.3", "v4.4", "v4.5", "v4.6", "v4.7", "v4.8", "v4.9", "v4.10",
                              "v4.11", "v4.12", "v4.13", "v4.14", "v4.15", "v4.16", "v4.17", "v4.18", "v4.19", "v4.20",
                              "v5.0", "v5.1", "v5.2", "v5.3", "v5.4", "v5.5", "v5.6", "v5.7", "v5.8", "v5.9"]

    clang_gen_ir_cmd = ""
    # print(file_name)
    if cur_commit_hash_ver in linux_all_compiler_cmds:
        if file_name in linux_all_compiler_cmds[cur_commit_hash_ver]:
            logging.info("Compiler cmd from version: "+ cur_commit_hash_ver)
            clang_gen_ir_cmd = linux_all_compiler_cmds[cur_commit_hash_ver][file_name]

    kernel_sorted_versions = sorted_kernel_versions

    cur_idx = kernel_sorted_versions.index(cur_commit_hash_ver)
    pre_idx = cur_idx - 1
    post_idx = cur_idx + 1

    # Searching in the neighborhood kernel version to seek for compiler command
    if clang_gen_ir_cmd == "":
        while  pre_idx >= 0 or post_idx < len(kernel_sorted_versions):
            if pre_idx >=0:
                pre_ver = kernel_sorted_versions[pre_idx]
                if pre_ver in linux_all_compiler_cmds:
                    if file_name in linux_all_compiler_cmds[pre_ver]:
                        logging.info("Compiler cmd from version: "+ pre_ver)
                        clang_gen_ir_cmd = linux_all_compiler_cmds[pre_ver][file_name]
                        break
            if post_idx < len(kernel_sorted_versions):
                post_ver = kernel_sorted_versions[post_idx]
                if post_ver in linux_all_compiler_cmds:
                    if file_name in linux_all_compiler_cmds[post_ver]:
                        logging.info("Compiler cmd from version: "+ post_ver)
                        clang_gen_ir_cmd = linux_all_compiler_cmds[post_ver][file_name]
                        break
            pre_idx = pre_idx - 1
            post_idx = post_idx + 1
    # The original compiler cmds extraction approach
    # print(clang_gen_ir_cmd)
    # if cur_commit_hash_ver in linux_all_compiler_cmds:
    #     if file_name in linux_all_compiler_cmds[cur_commit_hash_ver]:
    #         logging.info("Clang compiler cmd from verison: " + cur_commit_hash_ver)
    #         clang_gen_ir_cmd = linux_all_compiler_cmds[cur_commit_hash_ver][file_name]
    # if clang_gen_ir_cmd == "":
    #     for ver in linux_all_compiler_cmds:
    #         if file_name in linux_all_compiler_cmds[ver]:
    #             logging.info("Clang compiler cmd from verison: " + ver)
    #             clang_gen_ir_cmd = linux_all_compiler_cmds[ver][file_name]

    return clang_gen_ir_cmd


# Perform docker cp task from <source> to <target>.
def exec_docker_cp_cmd(cur_commit_hash_ver, source, target):
    docker_cp_cmd = "docker cp kernel" + cur_commit_hash_ver \
                    + source + " " + target
    cmd = utility.exec_system_cmd(docker_cp_cmd, logging)
    logging.info("Docker copy code: " + str(cmd))


# Perform git reset, clang compiler and clang link task.
def perform_reset_clang_compiler_link(patched_file_name, patched_ir_file_name,
                                      cur_commit_hash_ver, reset_commit_hash,
                                      cur_commit_hash, clang_gen_ir_cmd,
                                      commit_dir, optimization_level, patched_tag):

    # roll back to specific version
    docker_git_reset_cmd = "docker exec -it kernel" + cur_commit_hash_ver \
                           + " bash -c 'cd /linux; git reset --hard " \
                           + reset_commit_hash + "'"
    cmd = utility.exec_system_cmd(docker_git_reset_cmd, logging)
    if cmd != 0:
        logging.info("Git reset error code: " + str(cmd))
        return

    # generate IR files
    docker_clang_gen_ir_cmd = 'docker exec -it kernel' + cur_commit_hash_ver \
                              + ' bash -c "cd /linux; ' + clang_gen_ir_cmd + '"'
    cmd = utility.exec_system_cmd(docker_clang_gen_ir_cmd, logging)
    if cmd != 0:
        logging.info("Docker exec ir error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/ir_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_ir_error.log")
        return

    # copy unpatched source code files and generated IR files into target directories.
    exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_file_name,
                       commit_dir + "/" + cur_commit_hash + "/clang_"
                       + patched_tag + "/" + optimization_level)
    exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_ir_file_name,
                       commit_dir + "/" + cur_commit_hash + "/clang_"
                       + patched_tag + "/" + optimization_level)

    # generate assembly file via clang -S
    patched_assembly_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".s"
    clang_assembly_cmd = "clang -S " + patched_ir_file_name + " -o " \
                         + patched_assembly_file_name + " 2> /linux/clang-S_error.log"
    docker_clang_gen_assembly_cmd = "docker exec -it kernel" + cur_commit_hash_ver \
                                    + " bash -c 'cd /linux; " + clang_assembly_cmd + "'"
    cmd = utility.exec_system_cmd(docker_clang_gen_assembly_cmd, logging)
    if cmd != 0:
        logging.info("Docker exec clang assembly error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/clang-S_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_clang-S_error.log")
    else:
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_assembly_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)

    # generate intel assembly file via llc --x86-asm-syntax=intel
    patched_assembly_intel_file_name = patched_file_name[
                                              :patched_file_name.rindex(".")] + "_intel.s"
    llc_assembly_intel_cmd = "llc --x86-asm-syntax=intel " + patched_ir_file_name \
                             + " -o " + patched_assembly_intel_file_name \
                             + " 2> /linux/llc-assembly_error.log"
    docker_llc_gen_assembly_intel_cmd = "docker exec -it kernel" + cur_commit_hash_ver \
                                        + " bash -c 'cd /linux; " + llc_assembly_intel_cmd + "'"
    logging.info(docker_llc_gen_assembly_intel_cmd)
    cmd = os.system(docker_llc_gen_assembly_intel_cmd)
    if cmd != 0:
        logging.info("Docker exec llc intel assembly error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/llc-assembly_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_llc-assembly_error.log")
    else:
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_assembly_intel_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)

    # generate static link binary via clang -c
    patched_binary_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".o"
    clang_static_link_binary_cmd = "clang -c " + patched_assembly_file_name + " -o " \
                                   + patched_binary_file_name + " 2> /linux/clang-c_error.log"
    docker_clang_static_link_binary_cmd = "docker exec -it kernel" + cur_commit_hash_ver \
                                          + " bash -c 'cd /linux; " + clang_static_link_binary_cmd + "'"
    logging.info(docker_clang_static_link_binary_cmd)
    cmd = os.system(docker_clang_static_link_binary_cmd)
    if cmd != 0:
        logging.info("Docker exec clang static link error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/clang-c_error.log" ,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_clang-c_error.log")
    else:
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_binary_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)

    # generate intel static binary via clang -c
    patched_binary_intel_file_name = patched_file_name[:patched_file_name.rindex(".")] + "_intel.o"
    clang_static_link_intel_binary_cmd = "clang -c " + patched_assembly_intel_file_name \
                                         + " -o " + patched_binary_intel_file_name \
                                         + " 2> /linux/clang-c_intel_error.log"
    docker_clang_static_link_intel_binary_cmd = "docker exec -it kernel" + cur_commit_hash_ver \
                                                + " bash -c 'cd /linux; " + clang_static_link_intel_binary_cmd + "'"
    cmd = utility.exec_system_cmd(docker_clang_static_link_intel_binary_cmd, logging)
    if cmd != 0:
        logging.info("Docker exec clang static link intel error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/clang-c_intel_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_" + patched_tag
                           + "/" + optimization_level + "/" + patched_tag + "_clang-c_intel_error.log")
    else:
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_binary_intel_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)


# Get patched source code files, dependent paths and then generate patched IR,
# assembly and binary files for linux Kernel case
@with_goto
def extract_kernel_commit_files_and_clang_gen_ir_assembly_binary_files(commit_dir,
                                                                       commit_message_file,
                                                                       cur_commit_hash,
                                                                       pre_commit_hash,
                                                                       linux_all_compiler_cmds,
                                                                       linux_all_commits_stat_info):

    optimizations = ["default", "no", "O0", "O1", "O2", "O3", "Os"]
    # seek the kernel version of <cur_commit_hash>
    cur_commit_hash_ver = github_commit_operations.get_version_of_commit_hash(cur_commit_hash,
                                                                              linux_all_commits_stat_info)
    logging.info("Current kernel version:" + cur_commit_hash_ver)
    # if cur_commit_hash_ver != "v5.1":
    #     return
    if cur_commit_hash_ver.startswith("v2.6"):
        cur_commit_hash_ver = "v3.0"
        logging.info("No available kernel image, use kernel version v3.0 for replace.")
    commit_info, commit_file_to_info = github_commit_operations.\
        get_statistical_info_from_comit_message(commit_dir,
                                                commit_message_file,
                                                cur_commit_hash, logging)

    # start the built container environment
    docker_init_cmd = "docker run -itd --name kernel" + cur_commit_hash_ver \
                      + " mykernel:ClangBuild" + cur_commit_hash_ver + " /bin/bash"
    cmd = utility.exec_system_cmd(docker_init_cmd, logging)
    if cmd != 0:
        logging.info("Docker run error code: " + str(cmd))
        return

    if not os.path.exists(commit_dir + "/" + cur_commit_hash):
        os.mkdir(commit_dir + "/" + cur_commit_hash)

    for patchedFile in commit_file_to_info:

        logging.info(commit_file_to_info[patchedFile])
        for optimization_level in optimizations:
            # extracting and compiling the unpatched file
            patched_before_file = commit_file_to_info[patchedFile]["before"]
            patched_before_file = patched_before_file[patched_before_file.index("/")+1:]
            patched_file_name_before = patched_before_file

            # print(patched_file_name_before)
            # print(cur_commit_hash_ver)
            clang_gen_ir_cmd = get_compiler_cmd(patched_file_name_before,
                                                cur_commit_hash_ver, linux_all_compiler_cmds)

            if clang_gen_ir_cmd == "":
                logging.info("No compiler cmds for "+ patched_file_name_before)
                continue
            else:
                # Notice! do not break the original compiler cmds
                # clang_gen_ir_cmd = clang_gen_ir_cmd.replace("\'","\\'")
                clang_gen_ir_cmd = clang_gen_ir_cmd.replace('\"', '\\"')
                clang_gen_ir_cmd = clang_gen_ir_cmd.replace("-c ", "")
                for o in kernel_optimization_levels:
                    if optimization_level == "default":
                        continue
                    if optimization_level == "no":
                        clang_gen_ir_cmd = clang_gen_ir_cmd.replace("-" + o, "")
                    else:
                        clang_gen_ir_cmd = clang_gen_ir_cmd.replace("-" + o, "-" + optimization_level)
                clang_gen_ir_cmd = clang_gen_ir_cmd + " 2> /linux/ir_error.log"

            patched_ir_file_name_before = patched_file_name_before[:patched_file_name_before.rindex(".")] +".ll"
            ir_file_name = patched_ir_file_name_before[patched_ir_file_name_before.rindex("/")+1:]
            logging.info("UnPatched IR filePath: " + commit_dir + "/" + cur_commit_hash
                         + "/clang_before/" + optimization_level + "/" + ir_file_name)

            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/before/"
                              + optimization_level + "/" + ir_file_name):
                logging.info("LLVM IR code with " + optimization_level
                             + " optimization has been generated.")
                goto .after

            if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/clang_before"):
                os.mkdir(commit_dir + "/" + cur_commit_hash + "/clang_before")
            if not os.path.exists(commit_dir + "/" + cur_commit_hash +
                                  "/clang_before/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/clang_before/" + optimization_level)

            perform_reset_clang_compiler_link(patched_file_name_before,
                                              patched_ir_file_name_before,
                                              cur_commit_hash_ver, pre_commit_hash,
                                              cur_commit_hash, clang_gen_ir_cmd,
                                              commit_dir, optimization_level, "before")

            label .after # extracting and compiling the patched files
            patched_after_file = commit_file_to_info[patchedFile]["after"]
            patched_after_file = patched_after_file[patched_after_file.index("/")+1:]
            patched_file_name_after = patched_after_file

            patched_ir_file_name_after = patched_file_name_after[:patched_file_name_after.rindex(".")] + ".ll"
            logging.info("Patched IR file_name: " + commit_dir + "/" + cur_commit_hash
                         + "/clang_after/" + optimization_level + "/" + ir_file_name)

            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/after/"
                              + optimization_level + "/" + ir_file_name):
                logging.info("LLVM IR code with " + optimization_level
                             + " optimization has been generated.")
                continue

            if not os.path.exists(commit_dir+"/"+cur_commit_hash):
                os.mkdir(commit_dir+"/"+cur_commit_hash)
            if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/clang_after"):
                os.mkdir(commit_dir + "/" + cur_commit_hash + "/clang_after")
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/clang_after/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/clang_after/" + optimization_level)

            perform_reset_clang_compiler_link(patched_file_name_after,
                                              patched_ir_file_name_after,
                                              cur_commit_hash_ver, cur_commit_hash,
                                              cur_commit_hash, clang_gen_ir_cmd,
                                              commit_dir, optimization_level, "after")

    # Stop and remove the opened container environment
    docker_stop_cmd = "docker stop kernel" + cur_commit_hash_ver
    cmd = utility.exec_system_cmd(docker_stop_cmd, logging)
    if cmd != 0:
        logging.info("error code: "+ str(cmd))

    docker_rm_cmd = "docker rm kernel" + cur_commit_hash_ver
    cmd = utility.exec_system_cmd(docker_rm_cmd, logging)
    if cmd != 0:
        logging.info("error code: "+ str(cmd))


# Perform git reset, gcc compiler and gcc link task.
def perform_reset_gcc_compiler_link(patched_file_name,
                                    patched_assembly_file_name,
                                    cur_commit_hash_ver, reset_commit_hash,
                                    cur_commit_hash, gcc_gen_assembly_cmd,
                                    commit_dir, optimization_level, patched_tag):

    # roll back to specific version
    docker_git_reset_cmd = "docker exec -it kernel" + cur_commit_hash_ver \
                           + " bash -c 'cd /linux; git reset --hard " \
                           + reset_commit_hash + "'"
    cmd = utility.exec_system_cmd(docker_git_reset_cmd, logging)
    if cmd != 0:
        logging.info("Docker reset error code: " + str(cmd))
        return

    # generate assembly file via gcc compiler cmd
    docker_gcc_gen_assembly_cmd = 'docker exec -it kernel' + cur_commit_hash_ver \
                                  + ' bash -c "cd /linux; ' + gcc_gen_assembly_cmd + '"'
    cmd = utility.exec_system_cmd(docker_gcc_gen_assembly_cmd, logging)
    if cmd != 0:
        logging.info("Docker assembly error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/assembly_error.log",
                           commit_dir + "/" + cur_commit_hash + "/gcc_" + patched_tag
                           + "/" + optimization_level + "/gcc_"
                           + patched_tag + "_assembly_error.log")
        return

    if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_"+ patched_tag):
        os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_"+ patched_tag)
    if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_"
                          + patched_tag + "/" + optimization_level):
        os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_"
                 + patched_tag + "/" + optimization_level)

    # copy the source code files and generated assembly files into target directories
    exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_file_name,
                       commit_dir + "/" + cur_commit_hash + "/gcc_"
                       + patched_tag + "/" + optimization_level)
    exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/" + patched_assembly_file_name,
                       commit_dir + "/" + cur_commit_hash + "/gcc_"
                       + patched_tag + "/" + optimization_level)

    # generate static link binary via gcc -c
    patched_binary_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".o"
    docker_gcc_gen_binary_cmd = 'docker exec -it kernel' + cur_commit_hash_ver \
                                + ' bash -c "cd /linux; gcc -c ' + patched_assembly_file_name \
                                + " -o " + patched_binary_file_name \
                                + ' 2> /linux/binary_error.log"'
    cmd = utility.exec_system_cmd(docker_gcc_gen_binary_cmd, logging)
    if cmd != 0:
        logging.info("Docker gcc -c error code: " + str(cmd))
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/binary_error.log",
                           commit_dir + "/" + cur_commit_hash + "/gcc_"
                           + patched_tag + "/" + optimization_level
                           + "/" "gcc_" + patched_tag + "_binary_error.log")
    else:
        exec_docker_cp_cmd(cur_commit_hash_ver, ":/linux/"+patched_binary_file_name,
                           commit_dir + "/" + cur_commit_hash + "/gcc_"
                           + patched_tag + "/" + optimization_level)


# Get patched source code files, dependent paths and then generate assembly and binary files for linux Kernel case
@with_goto
def extract_kernel_commit_files_and_gcc_gen_assembly_binary_files(commit_dir, commit_message_file,
                                                                  cur_commit_hash, pre_commit_hash,
                                                                  linux_all_compiler_cmds,
                                                                  linux_all_commits_stat_info):

    optimizations = ["default", "no", "O0", "O1", "O2", "O3", "Os"]
    # seek the kernel version of <cur_commit_hash>
    cur_commit_hash_ver = github_commit_operations.\
        get_version_of_commit_hash(cur_commit_hash, linux_all_commits_stat_info)
    # if cur_commit_hash_ver != "v4.15":
    #     return
    logging.info("Current kernel version:" + cur_commit_hash_ver)
    unbuilt_kernel_versions = ["v2.6.12", "v2.6.13", "v2.6.16", "v2.6.17",
                               "v2.6.19", "v2.6.20", "v2.6.21"]
    if cur_commit_hash_ver in unbuilt_kernel_versions:
        cur_commit_hash_ver = "v3.0"
        logging.info("No available kernel image, use kernel version v3.0 for replace.")
    commit_info, commit_file_to_info = github_commit_operations.\
        get_statistical_info_from_comit_message(commit_dir, commit_message_file,
                                                cur_commit_hash, logging)

    # start the built container environment
    docker_init_cmd = "docker run -itd --name kernel" + cur_commit_hash_ver \
                      + " mykernel:GCCBuild" + cur_commit_hash_ver + " /bin/bash"
    cmd = utility.exec_system_cmd(docker_init_cmd, logging)
    if cmd != 0:
        logging.info("Docker run error code: " + str(cmd))
        return

    for patchedFile in commit_file_to_info:

        logging.info(commit_file_to_info[patchedFile])
        for optimization_level in optimizations:
            # extracting the file before patched

            patched_before_file = commit_file_to_info[patchedFile]["before"]
            patched_before_file = patched_before_file[patched_before_file.index("/")+1:]
            patched_file_name_before = patched_before_file

            # print(patched_file_name_before)
            # print(cur_commit_hash_ver)
            gcc_gen_assembly_cmd = get_compiler_cmd(patched_file_name_before,
                                                    cur_commit_hash_ver,
                                                    linux_all_compiler_cmds)

            if gcc_gen_assembly_cmd == "":
                logging.info("No compiler cmds for " + patched_file_name_before)
                continue
            else:
                gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace('\"', '\\"')
                gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace("-c ", "")
                # Remove -O2 option would cause unexpected compilation errors.
                for o in kernel_optimization_levels:
                    if optimization_level == "default":
                        continue
                    if optimization_level == "no":
                        gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace("-" + o, "")
                    else:
                        gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace("-" + o,
                                                                            "-" + optimization_level)
                gcc_gen_assembly_cmd = gcc_gen_assembly_cmd + " 2> /linux/assembly_error.log"

            patched_assembly_file_name_before = patched_file_name_before[
                                                :patched_file_name_before.rindex(".")] + "_gcc.s"
            assembly_file_name = patched_assembly_file_name_before[
                                 patched_assembly_file_name_before.rindex("/")+1:]
            logging.info("UnPatched Assembly filePath: " + commit_dir + "/"
                         + cur_commit_hash + "/gcc_before/" + assembly_file_name)

            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_before/"
                              + optimization_level + "/" + assembly_file_name):
                logging.info("Assembly code with " + optimization_level
                             + " optimization has been generated.")
                goto .after

            if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_before"):
                os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_before")
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/gcc_before/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/gcc_before/" + optimization_level)

            perform_reset_gcc_compiler_link(patched_file_name_before,
                                            patched_assembly_file_name_before,
                                            cur_commit_hash_ver,
                                            pre_commit_hash, cur_commit_hash,
                                            gcc_gen_assembly_cmd, commit_dir,
                                            optimization_level, "before")

            label .after
            patched_after_file = commit_file_to_info[patchedFile]["after"]
            patched_after_file = patched_after_file[patched_after_file.index("/")+1:]
            patched_file_name_after = patched_after_file

            patched_assembly_file_name_after = patched_file_name_after[
                                               :patched_file_name_after.rindex(".")]+ "_gcc.s"
            logging.info("Patched Assembly file_name: " + commit_dir + "/" +
                         cur_commit_hash + "/gcc_after/" + optimization_level
                         + "/" + assembly_file_name)

            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_after/"
                              + optimization_level + "/" + assembly_file_name):
                logging.info("Assembly code with " + optimization_level
                             + " optimization has been generated.")
                continue

            if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_after"):
                os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_after")
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/gcc_after/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/gcc_after/" + optimization_level)

            perform_reset_gcc_compiler_link(patched_file_name_after,
                                            patched_assembly_file_name_after,
                                            cur_commit_hash_ver, cur_commit_hash,
                                            cur_commit_hash, gcc_gen_assembly_cmd,
                                            commit_dir, optimization_level, "after")

    # Stop and remove the opened container environment
    docker_stop_cmd = "docker stop kernel" + cur_commit_hash_ver
    cmd = utility.exec_system_cmd(docker_stop_cmd, logging)
    if cmd != 0:
        logging.info("error code: "+ str(cmd))

    docker_rm_cmd = "docker rm kernel" + cur_commit_hash_ver
    cmd = utility.exec_system_cmd(docker_rm_cmd, logging)
    if cmd != 0:
        logging.info("error code: "+ str(cmd))


# Get patched source code files, dependent paths and then generate assembly and binary files for common software
@with_goto
def extract_common_commit_files_and_gen_ir_assembly_binary_files(commit_dir, commit_message_file,
                                                                 cur_commit_hash, nextCommitHash,
                                                                 software_root_dir_path, softProject,
                                                                 software_dir, compiler_option_path):

    optimizations = ["no", "O0", "O1", "O2", "O3", "Os"]

    commit_info, commit_file_to_info = github_commit_operations.\
        get_statistical_info_from_comit_message(commit_dir, commit_message_file,
                                                cur_commit_hash, logging)

    for patchedFile in commit_file_to_info:
        logging.info("return to software root directory.")
        try:
            os.chdir(software_root_dir_path)
        except Exception as e:
            logging.info(e)
            logging.info("unable to return root directory.")

        logging.info(commit_file_to_info[patchedFile])

        # if os.path.exists(commit_dir+"/"+cur_commit_hash+"/before"):
        #     print("unpatched source code and IR information have been extracted.")
        #     goto .after

        # extracting the source code file and generate IR files before patch
        label.before
        patched_before_file = commit_file_to_info[patchedFile]["before"]
        patched_before_file = patched_before_file[patched_before_file.index("/") + 1:]

        squash_num = patched_before_file.count("/")
        logging.info(patched_before_file)
        patched_before_file_dir = "./"
        patched_file_name_before = patched_before_file

        if squash_num > 0:
            patched_before_file_dir = patched_before_file[:patched_before_file.rindex("/")]
            patched_file_name_before = patched_before_file[patched_before_file.rindex("/") + 1:]

        patched_ir_file_name_before = patched_file_name_before[
                                      :patched_file_name_before.rindex(".")] + ".ll"

        if os.path.exists(commit_dir + "/" + cur_commit_hash + "/before/"
                          + patched_ir_file_name_before):
            logging.info("LLVM IR code has been generated.")
            goto.after

        # roll back to unpathced version
        git_rest_cmd = 'git reset --hard ' + nextCommitHash
        cmd = utility.exec_system_cmd(git_rest_cmd, logging)
        if cmd != 0:
            logging.info("error code: " + str(cmd))
            goto.after
        # print(patched_before_file_dir)
        # print(patched_file_name_before)
        if not os.path.exists(software_root_dir_path + "/" + patched_before_file):
            print("file not exists")
            goto.after

        # software_build_dependence_operation.perform_software_build(software_root_dir_path, software_dir)

        include_cmds = software_build_dependence_operation.\
            extract_common_compiler_dependence(software_dir, squash_num,
                                               patched_before_file_dir, logging)

        # generate IR files
        patched_ir_file_name_before = patched_file_name_before[
                                      :patched_file_name_before.rindex(".")] + ".ll"

        if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/clang_before"):
            os.mkdir(commit_dir + "/" + cur_commit_hash + "/clang_before")

        for optimization_level in optimizations:
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/clang_before/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/clang_before/" + optimization_level)
            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/clang_before/"
                              + optimization_level + "/" + patched_ir_file_name_before):
                continue
            perform_common_clang_compiler_link(include_cmds, optimization_level,
                                               patched_file_name_before,
                                               patched_ir_file_name_before,
                                               commit_dir, cur_commit_hash, "before")

        # generate assembly files
        patched_assembly_file_name_before = patched_file_name_before[
                                            :patched_file_name_before.rindex(".")] + "_gcc.s"

        assembly_file_name = ""
        if patched_assembly_file_name_before.find("/") != -1:
            assembly_file_name = patched_assembly_file_name_before[
                                 patched_assembly_file_name_before.rindex("/") + 1:]
        else:
            assembly_file_name = patched_assembly_file_name_before
        logging.info(
            "UnPatched Assembly filePath: " + commit_dir + "/" + cur_commit_hash
            + "/gcc_before/" + assembly_file_name)

        if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_before"):
            os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_before")

        for optimization_level in optimizations:
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/gcc_before/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/gcc_before/" + optimization_level)
            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_before/"
                              + optimization_level + "/"
                              + patched_assembly_file_name_before):
                continue
            perform_common_gcc_compiler_link(include_cmds, optimization_level,
                                             patched_file_name_before,
                                             patched_assembly_file_name_before,
                                             commit_dir, cur_commit_hash, "before")

        label .after # extracting the source code file and generate IR files after patch
        patched_after_file = commit_file_to_info[patchedFile]["after"]
        patched_after_file = patched_after_file[patched_after_file.index("/") + 1:]

        squash_num = patched_after_file.count("/")
        logging.info(patched_after_file)
        logging.info(squash_num)
        patched_after_file_dir = "./"
        patched_file_name_after = patched_after_file

        if squash_num > 0:
            patched_after_file_dir = patched_after_file[:patched_after_file.rindex("/")]
            patched_file_name_after = patched_after_file[patched_after_file.rindex("/") + 1:]

        patched_ir_file_name_after = patched_file_name_after[
                                     :patched_file_name_after.rindex(".")] + ".ll"
        if os.path.exists(commit_dir + "/" + cur_commit_hash + "/after/"
                          + patched_ir_file_name_after):
            logging.info("LLVM IR code has been generated.")
            continue
        # return back to git root directory
        logging.info("return to software root directory.")
        try:
            os.chdir(software_root_dir_path)
        except Exception as e:
            logging.info("Error: {}\n unable to return root directory.".format(e))

        # roll back to patched version
        git_rest_cmd = 'git reset --hard ' + cur_commit_hash
        cmd = utility.exec_system_cmd(git_rest_cmd, logging)
        if cmd != 0:
            logging.info("error code: " + str(cmd))
            continue

        if not os.path.exists(software_root_dir_path + "/" + patched_after_file):
            print("source code file not exists")
            continue

        # software_build_dependence_operation.perform_software_build(software_root_dir_path, software_dir)
        include_cmds = software_build_dependence_operation.\
            extract_common_compiler_dependence(software_dir, squash_num,
                                               patched_after_file_dir, logging)

        # generate IR files
        patched_ir_file_name_after = patched_file_name_after[
                                     :patched_ir_file_name_after.rindex(".")] + ".ll"

        if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/clang_after"):
            os.mkdir(commit_dir + "/" + cur_commit_hash + "/clang_after")

        for optimization_level in optimizations:
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/clang_after/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/clang_after/" + optimization_level)
            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/clang_after/"
                              + optimization_level + "/" + patched_ir_file_name_after):
                continue
            perform_common_clang_compiler_link(include_cmds, optimization_level,
                                               patched_file_name_after,
                                               patched_ir_file_name_after,
                                               commit_dir, cur_commit_hash, "after")

        # generate assembly files
        patched_assembly_file_name_after = patched_file_name_after[
                                           :patched_file_name_after.rindex(".")] + "_gcc.s"
        assembly_file_name = ""
        if patched_assembly_file_name_after.find("/") != -1:
            assembly_file_name = patched_assembly_file_name_after[
                                 patched_assembly_file_name_after.rindex("/") + 1:]
        else:
            assembly_file_name = patched_assembly_file_name_after
        logging.info(
            "UnPatched Assembly filePath: " + commit_dir + "/" + cur_commit_hash
            + "/gcc_after/" + assembly_file_name)

        if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_after"):
            os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_after")

        for optimization_level in optimizations:
            if not os.path.exists(commit_dir + "/" + cur_commit_hash
                                  + "/gcc_after/" + optimization_level):
                os.mkdir(commit_dir + "/" + cur_commit_hash
                         + "/gcc_after/" + optimization_level)
            if os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_after/"
                              + optimization_level + "/" + patched_assembly_file_name_after):
                continue
            perform_common_gcc_compiler_link(include_cmds, optimization_level,
                                             patched_file_name_after,
                                             patched_assembly_file_name_after,
                                             commit_dir, cur_commit_hash, "after")


# Perform gcc compiler and clang link task.
def perform_common_gcc_compiler_link(include_cmds, optimization_level,
                                     patched_file_name,
                                     patched_assembly_file_name,
                                     commit_dir, cur_commit_hash, patch_tag):

    # generate assembly code
    gcc_gen_assembly_cmd = "gcc " + include_cmds + "-" + optimization_level \
                           + " -S " + patched_file_name + " -o " \
                           + patched_assembly_file_name + " 2> " \
                           + commit_dir + "/" + cur_commit_hash + "/gcc_" \
                           + patch_tag + "/" + optimization_level \
                           + "/gcc-S_error.log"
    if optimization_level == "no":
        gcc_gen_assembly_cmd = gcc_gen_assembly_cmd = "gcc " + include_cmds \
                                                      + "-S " + patched_file_name + " -o " \
                                                      + patched_assembly_file_name + " 2> " \
                                                      + commit_dir + "/" + cur_commit_hash \
                                                      + "/gcc_" + patch_tag + "/" \
                                                      + optimization_level + "/gcc-S_error.log"
    cmd = utility.exec_system_cmd(gcc_gen_assembly_cmd, logging)
    if cmd != 0:
        logging.info("error code: " + str(cmd))
        return
    shutil.copy(patched_file_name,
                commit_dir + "/" + cur_commit_hash + "/gcc_" + patch_tag
                + "/" + optimization_level)
    shutil.copy(patched_assembly_file_name,
                commit_dir + "/" + cur_commit_hash + "/gcc_" + patch_tag
                + "/" + optimization_level)

    # generate static link binary via gcc -c
    patched_binary_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".o"
    docker_gcc_gen_binary_cmd = "gcc -c " + patched_assembly_file_name + " -o " \
                                + patched_binary_file_name + " 2> " + commit_dir \
                                + "/" + cur_commit_hash + "/gcc_" + patch_tag + "/" \
                                + optimization_level + "/gcc-c_error.log"
    cmd = utility.exec_system_cmd(docker_gcc_gen_binary_cmd, logging)
    if cmd != 0:
        logging.info("error code: " + str(cmd))
        return
    shutil.copy(patched_binary_file_name,
                commit_dir + "/" + cur_commit_hash + "/gcc_"
                + patch_tag + "/" + optimization_level)


# Perform clang compiler and clang link task.
def perform_common_clang_compiler_link(include_cmds, optimization_level,
                                       patched_file_name,
                                       patched_ir_file_name,
                                       commit_dir, cur_commit_hash, patch_tag):

    # generate ir files
    # clang -I../crypto -I.. -I../include -emit-llvm -g -S <example>.c -o <example>.ll
    clang_gen_ir_cmd = "clang -w" + include_cmds + "-" + optimization_level \
                       + " -emit-llvm -g -S " + patched_file_name \
                       + " -o " + patched_ir_file_name \
                       + " 2> " + commit_dir + "/" + cur_commit_hash \
                       + "/clang_" + patch_tag + "/" \
                       + optimization_level + "/clang-S_error.log"
    if optimization_level == "no":
        clang_gen_ir_cmd = "clang -w" + include_cmds + "-emit-llvm -g -S " \
                           + patched_file_name + " -o " + patched_ir_file_name \
                           + " 2> " + commit_dir + "/" + cur_commit_hash \
                           + "/clang_" + patch_tag + "/" + optimization_level \
                           + "/clang-S_error.log"
    cmd = utility.exec_system_cmd(clang_gen_ir_cmd, logging)
    if cmd != 0:
        logging.info("error code: " + str(cmd))
        return
    shutil.copy(patched_file_name, commit_dir + "/" + cur_commit_hash + "/clang_"
                + patch_tag + "/" + optimization_level)
    shutil.copy(patched_ir_file_name, commit_dir + "/" + cur_commit_hash
                + "/clang_" + patch_tag + "/" + optimization_level)

    # generate static link binary via llc
    patched_binary_file_name = patched_ir_file_name + ".o"
    llc_assembly_cmd = "llc -march=x86-64 " + patched_ir_file_name \
                       + " -o " + patched_binary_file_name + " 2> " \
                       + commit_dir + "/" + cur_commit_hash + "/clang_" \
                       + patch_tag + "/" + optimization_level + "/llc_error.log"
    cmd = utility.exec_system_cmd(llc_assembly_cmd, logging)
    if cmd != 0:
        logging.info("error code: " + str(cmd))
        return
    shutil.copy(patched_binary_file_name,
                commit_dir + "/" + cur_commit_hash + "/clang_"
                + patch_tag + "/" + optimization_level)


def main():
    cur_path = os.getcwd()
    temp_path = cur_path + "/" + temp_dir
    if not os.path.exists(temp_path):
        os.makedirs(temp_path)
    compiler_option_path = cur_path + "/" + compiler_option_dir
    if not os.path.exists(compiler_option_path):
        print("No compile configuration directory.")
    logging.info(cur_path)
    logging.info(temp_path)
    logging.info(compiler_option_path)

    # Obtain all clang compiler cmds for linux kernel
    clang_build_cmd_file_list = utility.get_subfiles_from_dir(linux_clang_compiler_cmds_dir, ".json")
    linux_all_clang_compiler_cmds = {}
    for build_cmdFile in clang_build_cmd_file_list:
        ver = build_cmdFile.replace(".json","")
        ver = ver[ver.rindex("/")+1:]
        linux_all_clang_compiler_cmds[ver] = utility.file_to_object(build_cmdFile)

    linux_all_commits_stat_info = utility.file_to_object(linux_all_commits_stat_info_filepath)

    # Obtain all gcc compiler cmds for linux kernel
    gcc_build_cmd_file_list = utility.get_subfiles_from_dir(linux_gcc_compiler_cmds_dir, ".json")
    linux_all_gcc_compiler_cmds = {}
    for build_cmdFile in gcc_build_cmd_file_list:
        ver = build_cmdFile.replace(".json", "")
        ver = ver[ver.rindex("/") + 1:]
        linux_all_gcc_compiler_cmds[ver] = utility.file_to_object(build_cmdFile)

    commits_count = 0
    non_empty_count = 0
    succ_extract_count = 0

    for filename in os.listdir( commits_dir ):
        commit_path = commits_dir +"/"+ filename
        if os.path.isfile(commit_path):
            # print(filename)
            logging.info(filename)
            logging.info(commit_path)
            logging.info("This is the " + str(commits_count) + " vulnerability.")
            commits_count = commits_count + 1
            # if filename.count('.') >= 4:
            if filename.count('.') >= 2:
                info = filename.split('.')
                # for security patch dataset
                logging.info(info)
                # vuln_id = info[0]
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]
                # vuln_commit_hash = info[3]

                # for judgednon security patch dataset
                # vuln_commit_hash = info[0]
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]

                # for judged non security patch dataset
                vuln_software_project = info[0]
                vuln_software_dir = info[1]
                vuln_commit_hash = info[2]

                commit_dir = commits_dir +"/"+ filename[:filename.rindex(".")]
                # commit_dir = commits_dir + "/" + filename[:filename.rindex(".")]

                # if vuln_id != "CVE-2019-11811":
                #     continue
                if vuln_software_dir != "linux":
                    continue
                if vuln_software_project != "torvalds":
                    continue
                # print(filename.rindex("."))
                if vuln_software_dir in empty_project_list:
                    logging.info("The software is in empty list (Not exist).")
                    continue
                if os.path.exists(commit_dir+"/"+vuln_commit_hash+"/patch_info.txt"):
                    logging.info("The stat info patched commits has been extracted.")
                    # continue
                if not os.path.exists(commit_dir):
                    os.makedirs(commit_dir)

                non_empty_count = non_empty_count + 1
                if os.path.exists(commit_dir + "/" + vuln_commit_hash + "/gcc_after"):
                    succ_extract_count = succ_extract_count + 1

                os.chdir(temp_path)
                if not os.path.exists(temp_path + "/" + vuln_software_project):
                    os.makedirs(temp_path + "/" + vuln_software_project)
                os.chdir(temp_path + "/" + vuln_software_project)

                # Download software repository
                git_clone_cmd = 'git clone https://github.com/' + vuln_software_project \
                                + '/' + vuln_software_dir + '.git'
                utility.exec_system_cmd(git_clone_cmd, logging)

                software_path = temp_path + "/" + vuln_software_project + "/" + vuln_software_dir
                os.chdir(software_path)

                # Obtain the previous commit message hash
                # git log fc4e1ab4708a3eb87a107df7e085d0d8125c5171 -n 2 --pretty=oneline
                git_log_cmd = 'git log ' + vuln_commit_hash + \
                              ' -n 2 --pretty=oneline > ../commitsIdTemp.txt '
                cmd = utility.exec_system_cmd(git_log_cmd, logging)
                if cmd != 0:
                    logging.info("error code: "+ str(cmd))
                    continue

                vuln_pre_commit_hash = ""
                with open("../commitsIdTemp.txt", 'r') as f:
                    lines = f.readlines()
                    vuln_pre_commit_hash = lines[1].split()[0]
                logging.info(vuln_pre_commit_hash)

                if vuln_software_dir == "linux" and vuln_software_project == "torvalds":
                    extract_kernel_commit_files_and_clang_gen_ir_assembly_binary_files(commit_dir, commit_path,
                                                                                       vuln_commit_hash,
                                                                                       vuln_pre_commit_hash,
                                                                                       linux_all_clang_compiler_cmds,
                                                                                       linux_all_commits_stat_info)
                    extract_kernel_commit_files_and_gcc_gen_assembly_binary_files(commit_dir, commit_path,
                                                                                  vuln_commit_hash,
                                                                                  vuln_pre_commit_hash,
                                                                                  linux_all_gcc_compiler_cmds,
                                                                                  linux_all_commits_stat_info)
                else:
                    extract_common_commit_files_and_gen_ir_assembly_binary_files(commit_dir, commit_path,
                                                                                 vuln_commit_hash,
                                                                                 vuln_pre_commit_hash,
                                                                                 software_path,
                                                                                 vuln_software_project,
                                                                                 vuln_software_dir,
                                                                                 compiler_option_path)
                # break
        utility.terminal_clear()

    print("There are {} patched commits.".format(commits_count))
    print("There are {} non empty commits.".format(non_empty_count))
    print("There are {} successfully extracted commits.".format(succ_extract_count))


if __name__ == '__main__':
    main()
