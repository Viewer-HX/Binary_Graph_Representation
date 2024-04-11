
'''
    This script parses the building log of Linux kernel
    into json object containing compiler command
    Json object form {<source_code_file>,<gcc/clang ...>>}
'''
import os
import json

build_log_dir = "../../SoftwareBuildLog"
clang_log_prefix_name = "BuildLogClang"
gcc_log_prefix_name = "BuildLogGCC"
clang_compiler_cmd_dir = "../../Software_compiler_cmd/clang"
gcc_compiler_cmd_dir = "../../Software_compiler_cmd/gcc"


# Obtain specific file type list from dir
def get_subfiles_from_dir(directory, filetype):
    subfiles= []

    files = os.listdir(directory)
    for file in files:
        p = directory +"/"+ file
        if not os.path.isdir(p) and file.endswith(filetype):
            subfiles.append(p)

    return subfiles


# Read out json object
def file_to_object(json_file):
    data = {}
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data


# Write out json object
def object_to_file(json_file, json_object):
    with open(json_file, 'w') as f:
        json.dump(json_object, f)


# Parse clang building log into json object
def parse_clang_log(filename):
    compiler_cmds = []
    clang_gen_ir_cmds = {}

    print(filename)
    # version = filename[filename.index(clang_log_prefix_name):].replace(clang_log_prefix_name,"").replace(".txt","")
    # cmds_ver_file = clang_compiler_cmd_dir +"/"+ version +".json"
    with open(filename, 'r') as f:
        lines = f.readlines()
        print(len(lines))
        for line in lines:
            line = line.strip()
            # if '"' in line or "'" in line:
            #     line = line.replace('\"','\\"')
            #     line = line.replace("\'","\\'")
            if line.endswith(".c"):
                compiler_cmds.append(line)
                # print(line)
                cmd = line.split(' ')
                #  if cmd[-3] == "-o" and cmd[-4] == "-c":
                #print(line)
                #print(cmd)
                #if cmd[-3] != "-o":
                # print(cmd)
                cmd[-3] = "-g -S -emit-llvm"
                # cmd[-4] = "-emit-llvm"
                cmd[-2] = cmd[-1]
                tmp = cmd[-1]
                iroutput = tmp.replace(".c",".ll")
                cmd[-1] = "-o "+iroutput
                clang_gen_ir_cmds[tmp]= " ".join(cmd)
                # print(clang_gen_ir_cmds)
                # break
            # if ".c" in line:
            #     print(type(line))
            #     print(line)
            #     print(line.endswith(".c"))
            #     break

    print(len(compiler_cmds))
    print(len(clang_gen_ir_cmds))
    # object_to_file(cmds_ver_file, clang_gen_ir_cmds)
    return clang_gen_ir_cmds


# Parse gcc building log into json object
def parse_gcc_log(filename):
    compiler_cmds = []
    gcc_gen_assembly_cmds = {}

    print(filename)
    with open(filename, 'r') as f:
        lines = f.readlines()
        print(len(lines))
        for line in lines:
            line = line.strip()
            if line.endswith(".c"):
                compiler_cmds.append(line)
                cmd = line.split(' ')
                try:
                    if cmd[-4] == "-c":
                        cmd[-4] = "-g"
                        cmd[-3] = "-S"
                    else:
                        cmd[-3] = "-g -S"
                except Exception as e:
                    print(e)
                cmd[-2] = cmd[-1]
                tmp = cmd[-1]
                assembly_output = tmp.replace(".c","_gcc.s")
                cmd[-1] = "-o "+assembly_output
                gcc_gen_assembly_cmds[tmp]= " ".join(cmd)

    print(len(compiler_cmds))
    print(len(gcc_gen_assembly_cmds))

    return gcc_gen_assembly_cmds


def main():
    log_files_list = get_subfiles_from_dir(build_log_dir, ".txt")
    print(log_files_list)

    for log in log_files_list:
        print(log)
        if clang_log_prefix_name in log:
            software_project, software_dir = log[log.rindex('/')+1:log.index(clang_log_prefix_name)].split("---")
            cmds_ver_file = clang_compiler_cmd_dir + "/" + software_project.lower() \
                            + "---" + software_dir.lower() + ".json"
            if os.path.exists(cmds_ver_file):
                continue
            clang_gen_ir_cmds = parse_clang_log(log)
            object_to_file(cmds_ver_file, clang_gen_ir_cmds)

        if gcc_log_prefix_name in log:
            software_project, software_dir = log[log.rindex('/')+1:log.index(gcc_log_prefix_name):].split("---")
            cmds_ver_file = gcc_compiler_cmd_dir + "/" + software_project.lower() \
                            + "---" + software_dir.lower() + ".json"
            if os.path.exists(cmds_ver_file):
                continue
            gcc_gen_assembly_cmds = parse_gcc_log(log)
            object_to_file(cmds_ver_file, gcc_gen_assembly_cmds)


if __name__ == '__main__':
    main()