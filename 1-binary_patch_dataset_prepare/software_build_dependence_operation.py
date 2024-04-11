'''
    This script provides the build process for open source softwares,
    and also provide dependence path lookup methods for common source code files.
'''

import os
import utility

# Building operation for specific software
def perform_software_build( software_root_dir_path, software_dir, logging):
    if os.path.exists(software_root_dir_path+"/autogen.sh"):
        pre_build_cmd = './autogen.sh'
        logging.info(pre_build_cmd)
        os.system(pre_build_cmd)

    # cleanCmd = 'make clean'
    # logging.info(cleanCmd)
    # os.system(cleanCmd)

    pre_compiler_reconf_cmd = 'autoreconf -i --force'
    utility.exec_system_cmd(pre_compiler_reconf_cmd, logging)

    pre_compiler_conf_cmd = 'autoconf'
    utility.exec_system_cmd(pre_compiler_conf_cmd, logging)

    pre_compiler_autohead_cmd = 'autoheader'
    utility.exec_system_cmd(pre_compiler_autohead_cmd, logging)

    if software_dir == "openssl":
        configure_cmd = './Configure linux-x86_64'
        utility.exec_system_cmd(configure_cmd, logging)

        # make_cmd = 'make -j30'
        # utility.exec_system_cmd(make_cmd, logging)
    elif software_dir == "mono":
        pre_build_cmd = './autogen.sh'
        utility.exec_system_cmd(pre_build_cmd, logging)

        configure_cmd = './configure'
        utility.exec_system_cmd(configure_cmd, logging)

        # make_cmd = 'make -j30'
        # utility.exec_system_cmd(make_cmd, logging)
    elif software_dir == "libarchive":
        build_cmd = 'cmake .'
        utility.exec_system_cmd(build_cmd, logging)

        # make_cmd = 'make -j30'
        # utility.exec_system_cmd(make_cmd, logging)
    # elif software_dir == "redis":
    #     make_cmd = 'make -j30'
    #     utility.exec_system_cmd(make_cmd, logging)
    elif software_dir == "radare2":
        configure_cmd = './configure'
        utility.exec_system_cmd(configure_cmd, logging)
    elif software_dir == "krb5":
        os.chdir("src")
        pre_compiler_conf_cmd = 'autoconf'
        utility.exec_system_cmd(pre_compiler_conf_cmd, logging)

        pre_compiler_autohead_cmd = 'autoheader'
        utility.exec_system_cmd(pre_compiler_autohead_cmd, logging)

        configure_cmd = './configure'
        utility.exec_system_cmd(configure_cmd, logging)

        # make_cmd = 'make -j30'
        # utility.exec_system_cmd(make_cmd, logging)
        os.chdir("..")
    elif software_dir == "FFmpeg":
        configure_special1_cmd = './configure --disable-x86asm'
        utility.exec_system_cmd(configure_special1_cmd, logging)

        configure_special2_cmd = './configure --disable-yasm'
        utility.exec_system_cmd(configure_special2_cmd, logging)

        # make_cmd = 'make -j30'
        # utility.exec_system_cmd(make_cmd, logging)
    elif software_dir == "linux":
        logging.info("no handle for kernel")
    elif os.path.exists(software_root_dir_path+"/CMakeLists.txt"):
        if not os.path.exists(software_root_dir_path+"/build"):
            os.makedirs(software_root_dir_path+"/build")
        os.chdir(software_root_dir_path+"/build")
        cmake_cmd = 'cmake ..'
        utility.exec_system_cmd(cmake_cmd, logging)
        # with open(compiler_option_path+"/cmake.txt","r") as f:
        #     lines = f.readlines()
        #     for line in lines:
        #         line = line.strip()
        #         logging.info(line)
        #         os.system(line)
        os.chdir("..")
    else:
        # common compile operation
        config_cmd = './config'
        cmd = utility.exec_system_cmd(config_cmd, logging)
        if cmd != 0:
            logging.info("error code: "+ str(cmd))

        config2_cmd = './configure'
        cmd = utility.exec_system_cmd(config2_cmd, logging)
        if cmd != 0:
            logging.info("error code: "+ str(cmd))

    # makeDependenceCmd = 'make dependence'
    # cmd = utility.exec_system_cmd(makeDependenceCmd, logging)
    # if cmd != 0:
    #     logging.info("error code: "+ str(cmd))

    # make_cmd = 'make'
    # cmd = utility.exec_system_cmd(make_cmd, logging)
    # if cmd != 0:
    #     logging.info("make error code: "+ str(cmd))

# Extract dependence of compiler
def extract_common_compiler_dependence(software_dir, squash_num, patched_before_file_dir, logging):
    # extract dependent paths
    include_dirs = []
    if os.path.exists("include"):
        cur_include_dir = ""
        if squash_num > 0:
            for i in range(0, squash_num):
                cur_include_dir = cur_include_dir + "../"
        else:
            cur_include_dir = "./"
        include_dirs.append(cur_include_dir + "include")

    if squash_num > 0:
        # patched_before_file_dir = patched_before_file[:patched_before_file.rindex("/")]
        # patched_file_name_before = patched_before_file[patched_before_file.rindex("/")+1:]
        # print(os.getcwd())
        try:
            os.chdir(patched_before_file_dir)
        except Exception as e:
            logging.info(e)
            return ""
    # logging.info("inital dependence file")
    # logging.info(include_dirs)
    include_dirs = seek_dependence_files(squash_num, include_dirs, software_dir)
    # print(include_dirs)

    include_cmds = " "
    for includeDir in include_dirs:
        include_cmds = include_cmds + "-I" + includeDir + " "
    return include_cmds

# Get dependent paths from Makefile or Experience
def seek_dependence_files(squash_num, include_dirs, software_dir):
    # logging.info(squash_num)
    #include_dirs = []

    cur_include_dir = ".."
    cur_dir = ""
    for i in range(0,squash_num):
        include_dirs.append(cur_include_dir)
        cur_include_dir = cur_include_dir +"/.."
        cur_dir = cur_dir +"../"
    # logging.info("Root dir")
    # logging.info(cur_dir)

    if "krb5" in software_dir:
        cur_dir = cur_dir +"src/"
        include_dirs.append(cur_dir +"include")
    if os.path.exists(cur_dir +"build"):
        include_dirs.append(cur_dir +"build")
    if os.path.exists(cur_dir +"build/src"):
        buildDirs = utility.get_subdirs_from_dir(cur_dir +"build/src", [])
        for dir in buildDirs:
            if "CMakeFile" in dir:
                continue
            if dir not in include_dirs:
                include_dirs.append(dir)
    # logging.info("build dir")
    # logging.info(include_dirs)

    if os.path.exists(cur_dir +"src"):
        include_dirs.append(cur_dir +"src")

    if os.path.exists(cur_dir +"src/lib"):
        include_dirs.append(cur_dir +"src/lib")
        src_lib_dirs = utility.get_subdirs_from_dir(cur_dir +"src/lib", [])
        for d in src_lib_dirs:
            if d not in include_dirs:
                include_dirs.append(d)

    if "mono" in software_dir:
        if os.path.exists(cur_dir +"eglib/src"):
            include_dirs.append(cur_dir +"eglib/src")

    if os.path.exists(cur_dir +"build/src"):
        if "openjpeg" in software_dir:
            srcDirs = utility.get_subdirs_from_dir(cur_dir +"src/lib", [])
            for dir in srcDirs:
                if "CMakeFile" in dir:
                    continue
                if "openjp2" in dir and dir not in include_dirs:
                    include_dirs.append(dir)
    # logging.info("src dir")
    # logging.info(include_dirs)

    if os.path.exists(cur_dir +"deps") and os.path.isdir(cur_dir +"deps"):
        include_dirs.append(cur_dir +"deps")
        deps_dirs = utility.get_subdirs_from_dir(cur_dir +"deps", [])
        for dir in deps_dirs:
            if dir not in include_dirs:
                include_dirs.append(dir)

    if "radare2" in software_dir:
        if os.path.exists(cur_dir +"libr/include"):
            include_dirs.append(cur_dir +"libr/include")
    # softRootDir = cur_include_dir
    if squash_num > 1:
        parent_dirs = os.listdir('../')
        for d in parent_dirs:
            p = "../" + d
            if os.path.isdir(p):
                if p not in include_dirs:
                    include_dirs.append(p)

    if os.path.exists("Makefile"):
        #print("Makefile exists.")
        with open("Makefile", 'r') as mkf:
            lines = mkf.readlines()
            variables = []
            for line in lines:
                if line.startswith("INCLUDES="):
                    include_dirs = line[line.index('=')+1:].strip().split()
                    for includeDir in include_dirs:
                        if '$' in includeDir:
                            variable = includeDir[includeDir.index("(")+1:includeDir.index(")")]
                            variables.append(variable)
                        if '$' not in includeDir and "-I"  in includeDir :
                            # print(includeDir[2:])
                            if includeDir[2:] not in include_dirs:
                                include_dirs.append(includeDir[2:])
                    break

            for variable in variables:
                for line in lines:
                    if line.startswith(variable+"="):
                        include_dirs = line[line.index('=')+1:].strip().split()
                        for includeDir in include_dirs:
                            if '$' not in includeDir and "-I"  in includeDir :
                                # print(includeDir[2:])
                                if includeDir[2:] not in include_dirs:
                                    include_dirs.append(includeDir[2:])
                            if '$' not in includeDir and "-I"  not in includeDir :
                                if includeDir not in include_dirs:
                                    include_dirs.append(includeDir)
                        break
    return include_dirs