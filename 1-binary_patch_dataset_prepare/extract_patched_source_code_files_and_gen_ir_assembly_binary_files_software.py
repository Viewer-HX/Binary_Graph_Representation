
'''
    This script provides the following functions:
    1) extracts patched and unpatched source code files from patch related commit message;
    2) compiles the source code files into LLVM IR files, assembly files and binary files
    via gcc and clang with different optimization levels;
    3) especially for common software;
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
commits_dir = "/home/xu/SoftwarePatch/nonSecurityDataset/ProjectLibav"
# commits_dir = "/home/binaryf/Binary_database/SecretPatch/judged/negatives"
# commits_dir = "/home/binaryf/Binary_database/Crawler/KernelSecurityDataset"
# commits_dir = "/home/binaryf/Binary_database/Crawler/KernelSecurityDatasetx86v4"

temp_dir = "temp"
empty_project_list = ["openbsd-libssl", "appweb", "goahead" ] # non exists project , "goahead"
compiler_option_dir = "compileOption"

software_clang_compiler_cmds_dir = "/home/xu/Software_compiler_cmd/clang"
software_gcc_compiler_cmds_dir = "/home/xu/Software_compiler_cmd/gcc"
software_optimization_levels = ["O0", "O1", "O2", "O3", "Os"]

# built_projects = ["ffmpeg", "openssl", "imagemagick", "qemu", "libav", "wireshark"]
built_projects = ["openssl", "libav"]

# Record in different log files
log_file_name = "patchedSourceCodeFilesAndBinaryFiles-Extraction-Software-Info.log"
idx = 0
while os.path.exists("Log/"+ log_file_name+ str(idx)):
    idx = idx + 1
log_file_name = log_file_name + str(idx)
logging.basicConfig(level=logging.DEBUG,
                    filename="Log/"+ log_file_name,
                    filemode='w')


# Get correct IR or gcc assembly compiler cmds for source code file <file_name>
def get_compiler_cmd(file_name, software_info, all_compiler_cmds):

    clang_gen_ir_cmd = ""
    # print("test: ", file_name)
    # print("test: ", software_info)
    # print("test: ", all_compiler_cmds)
    if software_info in all_compiler_cmds:
        # print("test1")
        if file_name in all_compiler_cmds[software_info]:
            logging.info("Compiler cmd from version: " + software_info)
            clang_gen_ir_cmd = all_compiler_cmds[software_info][file_name]

    return clang_gen_ir_cmd


# Perform docker cp task from <source> to <target>.
def exec_docker_cp_cmd(software_project, source, target):
    docker_cp_cmd = "docker cp " + software_project \
                    + source + " " + target
    cmd = utility.exec_system_cmd(docker_cp_cmd, logging)
    logging.info("Docker copy code: " + str(cmd))


# Perform git reset, clang compiler and clang link task.
def perform_reset_clang_compiler_link(patched_file_name, patched_ir_file_name,
                                      softProject, software_dir, reset_commit_hash,
                                      cur_commit_hash, clang_gen_ir_cmd,
                                      commit_dir, optimization_level, patched_tag):

    # roll back to specific version
    docker_git_reset_cmd = "docker exec -it " + softProject \
                           + " bash -c 'cd /" + software_dir + "; git reset --hard " \
                           + reset_commit_hash + "'"
    cmd = utility.exec_system_cmd(docker_git_reset_cmd, logging)
    if cmd != 0:
        logging.info("Git reset error code: " + str(cmd))
        return

    # generate IR files
    docker_clang_gen_ir_cmd = 'docker exec -it ' + softProject \
                              + ' bash -c "cd /' + software_dir + '; ' + clang_gen_ir_cmd + '"'
    cmd = utility.exec_system_cmd(docker_clang_gen_ir_cmd, logging)
    if cmd != 0:
        logging.info("Docker exec ir error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/ir_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_ir_error.log")
        return

    # copy unpatched source code files and generated IR files into target directories.
    exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_file_name,
                       commit_dir + "/" + cur_commit_hash + "/clang_"
                       + patched_tag + "/" + optimization_level)
    exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_ir_file_name,
                       commit_dir + "/" + cur_commit_hash + "/clang_"
                       + patched_tag + "/" + optimization_level)

    # generate assembly file via clang -S
    patched_assembly_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".s"
    clang_assembly_cmd = "clang -S " + patched_ir_file_name + " -o " \
                         + patched_assembly_file_name + " 2> /" + software_dir + "/clang-S_error.log"
    docker_clang_gen_assembly_cmd = "docker exec -it " + softProject \
                                    + " bash -c 'cd /" + software_dir + "; " + clang_assembly_cmd + "'"
    cmd = utility.exec_system_cmd(docker_clang_gen_assembly_cmd, logging)
    if cmd != 0:
        logging.info("Docker exec clang assembly error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/clang-S_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_clang-S_error.log")
    else:
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_assembly_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)

    # generate intel assembly file via llc --x86-asm-syntax=intel
    patched_assembly_intel_file_name = patched_file_name[
                                              :patched_file_name.rindex(".")] + "_intel.s"
    llc_assembly_intel_cmd = "llc --x86-asm-syntax=intel " + patched_ir_file_name \
                             + " -o " + patched_assembly_intel_file_name \
                             + " 2> /" + software_dir + "/llc-assembly_error.log"
    docker_llc_gen_assembly_intel_cmd = "docker exec -it " + softProject \
                                        + " bash -c 'cd /" + software_dir + "; " + llc_assembly_intel_cmd + "'"
    logging.info(docker_llc_gen_assembly_intel_cmd)
    cmd = os.system(docker_llc_gen_assembly_intel_cmd)
    if cmd != 0:
        logging.info("Docker exec llc intel assembly error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/llc-assembly_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_llc-assembly_error.log")
    else:
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_assembly_intel_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)

    # generate static link binary via clang -c
    patched_binary_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".o"
    clang_static_link_binary_cmd = "clang -c " + patched_assembly_file_name + " -o " \
                                   + patched_binary_file_name + " 2> /" + software_dir + "/clang-c_error.log"
    docker_clang_static_link_binary_cmd = "docker exec -it " + softProject \
                                          + " bash -c 'cd /" + software_dir + "; " + clang_static_link_binary_cmd + "'"
    logging.info(docker_clang_static_link_binary_cmd)
    cmd = os.system(docker_clang_static_link_binary_cmd)
    if cmd != 0:
        logging.info("Docker exec clang static link error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/clang-c_error.log" ,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level + "/"
                           + patched_tag + "_clang-c_error.log")
    else:
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_binary_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)

    # generate intel static binary via clang -c
    patched_binary_intel_file_name = patched_file_name[:patched_file_name.rindex(".")] + "_intel.o"
    clang_static_link_intel_binary_cmd = "clang -c " + patched_assembly_intel_file_name \
                                         + " -o " + patched_binary_intel_file_name \
                                         + " 2> /" + software_dir + "/clang-c_intel_error.log"
    docker_clang_static_link_intel_binary_cmd = "docker exec -it " + softProject \
                                                + " bash -c 'cd /" + software_dir + "; " \
                                                + clang_static_link_intel_binary_cmd + "'"
    cmd = utility.exec_system_cmd(docker_clang_static_link_intel_binary_cmd, logging)
    if cmd != 0:
        logging.info("Docker exec clang static link intel error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/clang-c_intel_error.log",
                           commit_dir + "/" + cur_commit_hash + "/clang_" + patched_tag
                           + "/" + optimization_level + "/" + patched_tag + "_clang-c_intel_error.log")
    else:
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_binary_intel_file_name,
                           commit_dir + "/" + cur_commit_hash + "/clang_"
                           + patched_tag + "/" + optimization_level)


# Get patched source code files, dependent paths and then generate patched IR,
# assembly and binary files for common software case
@with_goto
def extract_common_commit_files_and_clang_gen_ir_assembly_binary_files(commit_dir, commit_message_file,
                                                                       cur_commit_hash, pre_commit_hash,
                                                                       softProject, software_dir,
                                                                       software_all_clang_compiler_cmds):
    optimizations = ["no", "O0", "O1", "O2", "O3", "Os"]
    commit_info, commit_file_to_info = github_commit_operations. \
        get_statistical_info_from_comit_message(commit_dir, commit_message_file,
                                                cur_commit_hash, logging)
    software_info = softProject + "---" + software_dir

    # start the built container environment
    docker_init_cmd = "docker run -itd --name " + softProject \
                      + " my" + softProject + ":ClangBuild" + " /bin/bash"
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
            clang_gen_ir_cmd = get_compiler_cmd(patched_file_name_before, software_info,
                                                software_all_clang_compiler_cmds)

            if clang_gen_ir_cmd == "":
                logging.info("No compiler cmds for "+ patched_file_name_before)
                continue
            else:
                # Notice! do not break the original compiler cmds
                # clang_gen_ir_cmd = clang_gen_ir_cmd.replace("\'","\\'")
                clang_gen_ir_cmd = clang_gen_ir_cmd.replace('\"', '\\"')
                clang_gen_ir_cmd = clang_gen_ir_cmd.replace("-c ", "")
                for o in software_optimization_levels:
                    if optimization_level == "default":
                        continue
                    if optimization_level == "no":
                        clang_gen_ir_cmd = clang_gen_ir_cmd.replace("-" + o, "")
                    else:
                        clang_gen_ir_cmd = clang_gen_ir_cmd.replace("-" + o, "-" + optimization_level)
                clang_gen_ir_cmd = clang_gen_ir_cmd + " 2> /" + software_dir + "/ir_error.log"

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
                                              softProject, software_dir, pre_commit_hash,
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
                                              softProject, software_dir, cur_commit_hash,
                                              cur_commit_hash, clang_gen_ir_cmd,
                                              commit_dir, optimization_level, "after")

    # Stop and remove the opened container environment
    docker_stop_cmd = "docker stop " + softProject
    cmd = utility.exec_system_cmd(docker_stop_cmd, logging)
    if cmd != 0:
        logging.info("error code: "+ str(cmd))

    docker_rm_cmd = "docker rm " + softProject
    cmd = utility.exec_system_cmd(docker_rm_cmd, logging)
    if cmd != 0:
        logging.info("error code: "+ str(cmd))


# Perform git reset, gcc compiler and gcc link task.
def perform_reset_gcc_compiler_link(patched_file_name,
                                    patched_assembly_file_name,
                                    softProject, software_dir,
                                    reset_commit_hash, cur_commit_hash,
                                    gcc_gen_assembly_cmd, commit_dir,
                                    optimization_level, patched_tag):

    # roll back to specific version
    docker_git_reset_cmd = "docker exec -it " + softProject \
                           + " bash -c 'cd /" + software_dir + "; git reset --hard " \
                           + reset_commit_hash + "'"
    cmd = utility.exec_system_cmd(docker_git_reset_cmd, logging)
    if cmd != 0:
        logging.info("Docker reset error code: " + str(cmd))
        return

    # generate assembly file via gcc compiler cmd
    docker_gcc_gen_assembly_cmd = 'docker exec -it ' + softProject \
                                  + ' bash -c "cd /' + software_dir + '; ' + gcc_gen_assembly_cmd + '"'
    cmd = utility.exec_system_cmd(docker_gcc_gen_assembly_cmd, logging)
    if cmd != 0:
        logging.info("Docker assembly error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/assembly_error.log",
                           commit_dir + "/" + cur_commit_hash + "/gcc_" + patched_tag
                           + "/" + optimization_level + "/gcc_"
                           + patched_tag + "_assembly_error.log")
        return

    if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_" + patched_tag):
        os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_" + patched_tag)
    if not os.path.exists(commit_dir + "/" + cur_commit_hash + "/gcc_"
                          + patched_tag + "/" + optimization_level):
        os.mkdir(commit_dir + "/" + cur_commit_hash + "/gcc_"
                 + patched_tag + "/" + optimization_level)

    # copy the source code files and generated assembly files into target directories
    exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_file_name,
                       commit_dir + "/" + cur_commit_hash + "/gcc_"
                       + patched_tag + "/" + optimization_level)
    exec_docker_cp_cmd(softProject, ":/" + software_dir + "/" + patched_assembly_file_name,
                       commit_dir + "/" + cur_commit_hash + "/gcc_"
                       + patched_tag + "/" + optimization_level)

    # generate static link binary via gcc -c
    patched_binary_file_name = patched_file_name[:patched_file_name.rindex(".")] + ".o"
    docker_gcc_gen_binary_cmd = 'docker exec -it kernel' + softProject \
                                + ' bash -c "cd /' + software_dir + '; gcc -c ' + patched_assembly_file_name \
                                + " -o " + patched_binary_file_name \
                                + ' 2> /' + software_dir + '/binary_error.log"'
    cmd = utility.exec_system_cmd(docker_gcc_gen_binary_cmd, logging)
    if cmd != 0:
        logging.info("Docker gcc -c error code: " + str(cmd))
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/binary_error.log",
                           commit_dir + "/" + cur_commit_hash + "/gcc_"
                           + patched_tag + "/" + optimization_level
                           + "/" "gcc_" + patched_tag + "_binary_error.log")
    else:
        exec_docker_cp_cmd(softProject, ":/" + software_dir + "/"+patched_binary_file_name,
                           commit_dir + "/" + cur_commit_hash + "/gcc_"
                           + patched_tag + "/" + optimization_level)


# Get patched source code files, dependent paths and then generate assembly
# and binary files for common software case
@with_goto
def extract_common_commit_files_and_gcc_gen_assembly_binary_files(commit_dir, commit_message_file,
                                                                  cur_commit_hash, pre_commit_hash,
                                                                  softProject, software_dir,
                                                                  software_all_gcc_compiler_cmds):

    optimizations = ["no", "O0", "O1", "O2", "O3", "Os"]
    commit_info, commit_file_to_info = github_commit_operations. \
        get_statistical_info_from_comit_message(commit_dir, commit_message_file,
                                                cur_commit_hash, logging)
    software_info = softProject + "---" + software_dir

    # start the built container environment
    docker_init_cmd = "docker run -itd --name " + softProject \
                      + " my" + softProject + ":GCCBuild" + " /bin/bash"
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
                                                    software_info,
                                                    software_all_gcc_compiler_cmds)

            if gcc_gen_assembly_cmd == "":
                logging.info("No compiler cmds for " + patched_file_name_before)
                continue
            else:
                gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace('\"', '\\"')
                gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace("-c ", "")
                # Remove -O2 option would cause unexpected compilation errors.
                for o in software_optimization_levels:
                    if optimization_level == "default":
                        continue
                    if optimization_level == "no":
                        gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace("-" + o, "")
                    else:
                        gcc_gen_assembly_cmd = gcc_gen_assembly_cmd.replace("-" + o,
                                                                            "-" + optimization_level)
                gcc_gen_assembly_cmd = gcc_gen_assembly_cmd + " 2> /" + software_dir + "/assembly_error.log"

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
                                            softProject, software_dir,
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
                                            softProject, software_dir,
                                            cur_commit_hash, cur_commit_hash,
                                            gcc_gen_assembly_cmd, commit_dir,
                                            optimization_level, "after")

    # Stop and remove the opened container environment
    docker_stop_cmd = "docker stop " + softProject
    cmd = utility.exec_system_cmd(docker_stop_cmd, logging)
    if cmd != 0:
        logging.info("error code: " + str(cmd))

    docker_rm_cmd = "docker rm " + softProject
    cmd = utility.exec_system_cmd(docker_rm_cmd, logging)
    if cmd != 0:
        logging.info("error code: " + str(cmd))


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

    # Obtain all clang compiler cmds for software
    clang_build_cmd_file_list = utility.get_subfiles_from_dir(software_clang_compiler_cmds_dir, ".json")
    software_all_clang_compiler_cmds = {}
    for build_cmdFile in clang_build_cmd_file_list:
        project_info = build_cmdFile.replace(".json","")
        software_all_clang_compiler_cmds[project_info.split("/")[-1]] = utility.file_to_object(build_cmdFile)

    # Obtain all gcc compiler cmds for software
    gcc_build_cmd_file_list = utility.get_subfiles_from_dir(software_gcc_compiler_cmds_dir, ".json")
    software_all_gcc_compiler_cmds = {}
    for build_cmdFile in gcc_build_cmd_file_list:
        # print("test build_cmdFile: ", build_cmdFile)
        project_info = build_cmdFile.replace(".json", "")
        # print("test project_info: ", project_info.split("/")[-1])
        software_all_gcc_compiler_cmds[project_info.split("/")[-1]] = utility.file_to_object(build_cmdFile)

    commits_count = 0

    for filename in os.listdir(commits_dir):
        commit_path = commits_dir + "/" + filename
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
                vuln_id = info[0]
                vuln_software_project = info[1]
                vuln_software_dir = info[2]
                vuln_commit_hash = info[3]

                # for non security patch dataset
                # vuln_commit_hash = info[0]
                # vuln_software_project = info[1]
                # vuln_software_dir = info[2]

                # for judged patch dataset
                # vuln_software_project = info[0]
                # vuln_software_dir = info[1]
                # vuln_commit_hash = info[2]

                commit_dir = commits_dir + "/" + filename[:filename.rindex(".")]
                # commit_dir = commits_dir + "/" + filename[:filename.rindex(".")]

                # if vuln_id != "CVE-2019-11811":
                #     continue
                if vuln_software_project not in built_projects:
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

                # non_empty_count = non_empty_count + 1
                # if os.path.exists(commit_dir + "/" + vuln_commit_hash + "/gcc_after"):
                #     succ_extract_count = succ_extract_count + 1

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
            
                extract_common_commit_files_and_clang_gen_ir_assembly_binary_files(commit_dir, commit_path,
                                                                                   vuln_commit_hash,
                                                                                   vuln_pre_commit_hash,
                                                                                   vuln_software_project.lower(),
                                                                                   vuln_software_dir.lower(),
                                                                                   software_all_clang_compiler_cmds)

                extract_common_commit_files_and_gcc_gen_assembly_binary_files(commit_dir, commit_path,
                                                                              vuln_commit_hash,
                                                                              vuln_pre_commit_hash,
                                                                              vuln_software_project.lower(),
                                                                              vuln_software_dir.lower(),
                                                                              software_all_gcc_compiler_cmds)
                    # break
        # utility.terminal_clear()

    print("There are {} patched commits.".format(commits_count))


if __name__ == '__main__':
    main()
