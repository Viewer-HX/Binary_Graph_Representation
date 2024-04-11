'''
    This file provide the basic file operation, execute external command
    file and jsonObject being converting to each other, etc.
'''

import json
import os
import sys
import curses

# Clear the output of terminal
def terminal_clear():
    curses.setupterm()
    e3 = curses.tigetstr('E3') or b''
    clear_screen_seq = curses.tigetstr('clear') or b''
    os.write(sys.stdout.fileno(), e3 + clear_screen_seq)

# Replace the Decimal into Hex
def int_to_hex(matched):
    int_str = matched.group("number"); #123
    int_value = int(int_str);
    if int_value < 16:
        return str(int_value)
    else:
        hex_value = str(hex(int_value))
        return hex_value
        # return hex_value[2:]+ "h"

# Read out json object
def file_to_object(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data

# Write out json object
def object_to_file(json_file, json_object):
    with open(json_file, 'w') as f:
        json.dump(json_object, f)

# Get all subfiles in dir
def get_subfiles_from_dir(directory, filetype):
    subfiles= []

    files = os.listdir(directory)
    for file in files:
        p = directory +"/"+ file
        if not os.path.isdir(p) and file.endswith(filetype):
            subfiles.append(p)

    return subfiles

# Get all subfiles in dir
def get_subfiles_with_prefix_from_dir(directory, prefix):
    subfiles= []

    files = os.listdir(directory)
    for file in files:
        p = directory + "/" + file
        if not os.path.isdir(p) and file.startswith(prefix):
            subfiles.append(file)

    return subfiles

# Get all subdires in the dir
def get_subdirs_from_dir(path, dir_list=[]):

    all_file_list=os.listdir(path)
    # print(all_file_list)
    for file in all_file_list:
        filepath=os.path.join(path,file)
        # print(file)
        if os.path.isdir(filepath):
            dir_list.append(filepath)
            get_subdirs_from_dir(filepath, dir_list)
    return dir_list

# Exec system cmd and output error code.
def exec_system_cmd(system_cmd, logger):
    logger.info(system_cmd)
    cmd = os.system(system_cmd)
    return cmd