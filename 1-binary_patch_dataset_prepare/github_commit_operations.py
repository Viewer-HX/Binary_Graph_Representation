import os
import utility


# Obtain software tag list
def get_tags_from_file(tag_file):
    tags = []
    with open(tag_file, 'r') as f:
        for line in f.readlines():
            tags.append(line.strip())
    return tags

# Get commit hashes between cur_tag and next_tag
def get_commit_hashes_between_tags(cur_tag, next_tag, software_dir):
    hashes_info = []
    # print("Current Version: Linux "+ next_tag)
    commits_temp_file = software_dir + 'TempCommits.txt'
    os.chdir(software_dir)
    git_log_commits_cmd = 'git log --pretty=oneline '+ cur_tag +'..'+ next_tag +' > ../' + commits_temp_file
    # print(git_log_commits_cmd)
    os.system(git_log_commits_cmd)
    os.chdir('..')

    with open(commits_temp_file, 'r') as f:
        lines = f.readlines()
        print(len(lines))
        for line in lines:
            h = line[:line.index(' ')]
            hashes_info.append(h)
    return hashes_info

# Get commit message for a hash
def get_commit_from_hash(cur_hash, commit_file, software_dir):
    os.chdir(software_dir)
    # git log fc4e1ab4708a3eb87a107df7e085d0d8125c5171 -n 2 --pretty=oneline
    git_log_cmd = 'git log '+ cur_hash +' -n 2 --pretty=oneline > ../commitsIdTemp.txt '
    print(git_log_cmd)
    cmd = os.system(git_log_cmd)
    if cmd != 0:
        print("error code: "+ str(cmd))

    pre_hash = ""
    with open("../commitsIdTemp.txt", 'r') as f:
        lines = f.readlines()
        try:
            pre_hash = lines[1].split()[0]
        except Exception as e:
            print(e)

    patch_diff_cmd = 'git diff ' + pre_hash +' '+ cur_hash +' > ../' + commit_file
    print(patch_diff_cmd)
    cmd = os.system(patch_diff_cmd)
    if cmd != 0:
        print("error code: "+ str(cmd))
    os.chdir('..')

# Get statistical changed information in commit_file into commit_stat_info_file
def get_statistical_info_from_commit_file(commit_file, commit_stat_info_file, temp_dir):
    changed_info = {}

    changed_file_index = 0;
    changed_file_to_index = {}
    changed_file_to_info = {}
    with open(temp_dir + "/" + commit_file, 'r') as pf:
        lines = pf.readlines()
        for line in lines:
            if "diff --git" in line:
                changed_files = line.split(" ")
                changed_file_before = changed_files[2].strip()
                changed_file_after = changed_files[3].strip()
                if changed_file_before.endswith(".c") \
                        and changed_file_after.endswith(".c"):
                    changed_file_index = changed_file_index + 1
                    changed_file_to_info[changed_file_index] = {"before": changed_file_before,
                                                                "after": changed_file_after}
                    changed_file_to_index[changed_file_index] = []

            if "@@" in line:
                try:
                    changed_funcs = line.split("@@")
                    changed_funcs_modify = changed_funcs[1].strip().split(" ")
                    changed_funcs_modify_before = changed_funcs_modify[0]
                    changed_funcs_modify_after =  changed_funcs_modify[1]
                    changed_func_info = changed_funcs[2].strip()
                    if changed_func_info != '\n' and changed_func_info != '':
                        changed_func_name = changed_func_info[:changed_func_info.index("(")]
                        changed_file_to_index[changed_file_index]\
                            .append({"before": changed_funcs_modify_before,
                                     "after": changed_funcs_modify_after,
                                    "function": changed_func_name})
                except Exception as e:
                    print("function name error:" + str(e))
                    continue

    changed_info["modifyFiles"] = changed_file_to_info
    changed_info["modifyFuncs"] = changed_file_to_index

    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    utility.object_to_file(temp_dir +"/"+ commit_stat_info_file, changed_info)

# Get statistical changed information of all commit messages between cur_tag and next_tag
def get_statistical_info_from_all_commits_between_tags(cur_tag, next_tag, temp_dir):
    commits_stat_info = {}
    hashes_info = get_commit_hashes_between_tags(cur_tag, next_tag)

    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)

    for h in hashes_info:
        commit_file = "tempCommit.txt"
        commit_stat_info_file = "tempCommitStatInfo.txt"
        get_commit_from_hash(h, commit_file)
        get_statistical_info_from_commit_file(commit_file, commit_stat_info_file)
        commits_stat_info[h] = utility.file_to_object(temp_dir +"/"+ commit_stat_info_file)
    return commits_stat_info

# Get all commits information between cur_tag and next_tag
def get_all_commits_between_tags(cur_tag, next_tag, software_dir):
    tags_commits_info = {}
    tags_commits_info["hash"] = []
    tags_commits_info["cve"] = []
    # print("Current Version: Linux "+ next_tag)
    commits_temp_file = software_dir + 'TempCommits.txt'
    os.chdir(software_dir)
    git_log_commits_cmd = 'git log --pretty=oneline '+ cur_tag +'..'+ next_tag +' > ../' + commits_temp_file
    # print(git_log_commits_cmd)
    os.system(git_log_commits_cmd)
    os.chdir('..')

    with open(commits_temp_file, 'r') as f:
        lines = f.readlines()
        print(len(lines))
        for line in lines:
            h = line[:line.index(' ')]
            tags_commits_info["hash"].append(h)
            message = line[line.index(' ')+1:]
    return tags_commits_info

# Get all software tags according to sequence in time
def get_all_tags_from_software(software_dir, tag_file):
    os.chdir(software_dir)
    # git_tag_cmd = 'git tag > ../' + tag_file
    #git for-each-ref --sort=taggerdate --format '%(refname) %' refs/tags
    git_tag_cmd = "git for-each-ref --sort=taggerdate --format '%(refname)' refs/tags > ../" + tag_file
    print(git_tag_cmd)
    os.system(git_tag_cmd)
    os.chdir("../")

# Get all patch statistical information from security_patched_commits_dir
def get_statistical_info_from_all_commits_in_dir(json_file, security_patched_commits_dir):
    patch_statistics = {}
    for filename in os.listdir( security_patched_commits_dir ):
        file_path = security_patched_commits_dir +"/"+ filename
        if os.path.isfile(file_path):
            if filename.count('.') >= 4:
                info = filename.split('.')
                vuln_id = info[0]
                vuln_software_project = info[1]
                vuln_software_dir = info[2]
                vuln_commit_hash = info[3]

                if vuln_software_project not in patch_statistics:
                    patch_statistics[vuln_software_project] = {}
                if vuln_software_dir not in patch_statistics[vuln_software_project]:
                    patch_statistics[vuln_software_project][vuln_software_dir] = {}
                    patch_statistics[vuln_software_project][vuln_software_dir]['count'] = 1
                    patch_statistics[vuln_software_project][vuln_software_dir]['vuln'] = [{"hash":vuln_commit_hash, "cve":vuln_id}]
                else:
                    count_temp = patch_statistics[vuln_software_project][vuln_software_dir]['count']
                    vulns_temp = patch_statistics[vuln_software_project][vuln_software_dir]['vuln']
                    count_temp = count_temp + 1
                    vulns_temp.append({"hash":vuln_commit_hash, "cve":vuln_id})
                    patch_statistics[vuln_software_project][vuln_software_dir]['count'] = count_temp
                    patch_statistics[vuln_software_project][vuln_software_dir]['vuln'] = vulns_temp
    utility.object_to_file(json_file, patch_statistics)

# Get the previous tag of cur_tag according current tag_file
def get_prev_tag(cur_tag, tag_file):
    pre_tag = ""
    tags = get_tags_from_file(tag_file)
    # print(tags)
    for i in range(len(tags)):
        tag = tags[i]
        tag = tag.replace("refs/tags/", "").strip()
        if tag == cur_tag:
            if i > 0:
                pre_tag = tags[i-1]
                pre_tag = pre_tag.replace("refs/tags/", "").strip()
    return pre_tag

# Get all statistical commits information of current tag
def get_statistical_info_of_all_commits_in_tag(cur_tag, tag_dir, tag_file):
    commits_stat_info = {}
    pre_tag = get_prev_tag(cur_tag, tag_file)
    if not os.path.exists(tag_dir +"/"+ cur_tag +".json"):
        commits_stat_info = get_statistical_info_from_all_commits_between_tags(pre_tag, cur_tag)
        utility.object_to_file(tag_dir +"/"+ cur_tag +".json", commits_stat_info)
    commits_stat_info = utility.file_to_object(tag_dir +"/"+ cur_tag +".json")
    # print(len(commits_stat_info))
    return commits_stat_info

# Get statistical commits information from vuln_stat_info into vuln_stat_info_file "linux-CVE.json"
def get_statistical_info_into_jsonfile(vuln_stat_info, vuln_stat_info_file, temp_dir):
    vuln_commits_stat_info = {}
    if not os.path.exists(vuln_stat_info_file):
        for ver in vuln_stat_info:
            vuln_commits_stat_info[ver] = {}
            for vuln in vuln_stat_info[ver]:
                h = vuln["hash"]
                commit_file = "tempCommit.txt"
                commit_stat_info_file = "tempCommitStatInfo.txt"
                get_commit_from_hash(h, commit_file)
                get_commit_from_hash(commit_file, commit_stat_info_file)
                vuln_commits_stat_info[ver][h] = utility.file_to_object(temp_dir +"/"+ commit_stat_info_file)

        utility.object_to_file(vuln_stat_info_file, vuln_commits_stat_info)
    vuln_commits_stat_info = utility.file_to_object(vuln_stat_info_file)
    return vuln_commits_stat_info

# Get stat info from patched commit message
def get_statistical_info_from_comit_message(commit_dir, commit_message_file,
                                            cur_commit_hash, logging):
    commit_info = {}

    commit_info["tag"] = "security"

    commit_file_idx = 0
    commit_file_to_func = {}
    commit_file_to_info = {}
    commit_file_to_lines = {}

    before_commit_start_line = 0
    after_commit_start_line = 0
    before_commit_idx = 0
    after_commit_idx = 0
    before_commit_len = 0
    after_commit_len = 0
    before_commit_lines = []
    after_commit_lines = []
    patched_func_name = ""
    patched_line_flag = False

    # Get patched Stat info from commit message
    with open(commit_message_file, 'r') as pf:
        lines = pf.readlines()
        for line in lines:
            if "diff --git" in line:
                patched_files = line.split(" ")
                patched_before_file = patched_files[2].strip()
                patched_after_file = patched_files[3].strip()

                if patched_before_file.endswith(".c") and patched_after_file.endswith(".c"):
                    commit_file_idx = commit_file_idx + 1
                    commit_file_to_info[commit_file_idx] = {"before": patched_before_file,
                                                            "after": patched_after_file}
                    commit_file_to_func[commit_file_idx] = []
                    commit_file_to_lines[commit_file_idx] = []

            if "@@" in line and commit_file_idx in commit_file_to_func:
                patched_line_flag = True
                patched_funcs = line.split("@@")
                patched_funcs_modify = patched_funcs[1].strip().split(" ")
                patched_func_modify_before = ""
                patched_func_modify_after = ""
                if len(patched_funcs_modify) > 1:
                    patched_func_modify_before = patched_funcs_modify[0]
                    patched_func_modify_after = patched_funcs_modify[1]
                else:
                    patched_funcs = patched_funcs_modify[0].strip()
                    if patched_funcs.startswith("-"):
                        patched_func_modify_before = patched_funcs
                    if patched_funcs.startswith("+"):
                        patched_func_modify_after = patched_funcs
                try:
                    before_commit_start_line, before_commit_len \
                        = patched_func_modify_before.split(",")
                    before_commit_start_line = int(before_commit_start_line[1:])
                    before_commit_len = int(before_commit_len)
                except Exception as e:
                    logging.info(e)

                try:
                    after_commit_start_line, after_commit_len \
                        = patched_func_modify_after.split(",")
                    after_commit_start_line = int(after_commit_start_line[1:])
                    after_commit_len = int(after_commit_len)
                except Exception as e:
                    logging.info(e)
                try:
                    patched_func_info = patched_funcs[2].strip()
                except Exception as e:
                    logging.info(e)
                    continue
                if patched_func_info != '\n' and patched_func_info != '':
                    try:
                        patched_func_name = patched_func_info[:patched_func_info.index("(")]
                        commit_file_to_func[commit_file_idx]\
                            .append({"before": patched_func_modify_before,
                                     "after": patched_func_modify_after,
                                     "function": patched_func_name})
                        logging.info(commit_file_to_func)
                    except Exception as e:
                        logging.info(e)

            if patched_line_flag and commit_file_idx in commit_file_to_lines:
                if line.startswith("-"):
                    before_commit_lines.append(before_commit_start_line
                                               + before_commit_idx - 1)
                    before_commit_idx = before_commit_idx + 1
                elif line.startswith("+"):
                    after_commit_lines.append(after_commit_start_line
                                              + after_commit_idx - 1)
                    after_commit_idx = after_commit_idx + 1
                else:
                    before_commit_idx = before_commit_idx + 1
                    after_commit_idx = after_commit_idx + 1
                if before_commit_idx >= before_commit_len \
                        or after_commit_idx >= after_commit_len:
                    commit_file_to_lines[commit_file_idx]\
                        .append({"before": before_commit_lines,
                                 "after": after_commit_lines,
                                 "function": patched_func_name})
                    logging.info(commit_file_to_lines)
                    patched_line_flag = False
                    before_commit_lines = []
                    after_commit_lines = []
                    before_commit_start_line = 0
                    after_commit_start_line = 0
                    before_commit_idx = 0
                    after_commit_idx = 0
                    before_commit_len = 0
                    after_commit_len = 0

    logging.info("patch changes in " + str(len(commit_file_to_info)) + " files.")
    logging.info(commit_file_to_info)
    if len(commit_file_to_info) == 1:
        logging.info("patch changes in one files.")
        logging.info("patch changes in " + str(len(commit_file_to_func)) + " functions.")
        logging.info(commit_file_to_func)
    commit_info["modifyFiles"] = commit_file_to_info
    commit_info["modifyFuncs"] = commit_file_to_func
    commit_info["modifyLines"] = commit_file_to_lines


    if not os.path.exists(commit_dir + "/" + cur_commit_hash):
        os.mkdir(commit_dir + "/" + cur_commit_hash)
    utility.object_to_file(commit_dir + "/" + cur_commit_hash
                           + "/patch_info.txt", commit_info)

    return commit_info, commit_file_to_info

# Seeking the kernel version of commit message
def get_version_of_commit_hash(cur_commit_hash, linux_all_commits_stat_info):
    cur_commit_hash_ver = ""
    # print(cur_commit_hash)
    find_flag = False
    for ver in linux_all_commits_stat_info:
        for h in linux_all_commits_stat_info[ver]["hash"]:
            if h == cur_commit_hash:
                cur_commit_hash_ver = ver
                find_flag = True
                break
        if find_flag:
            break
    cur_commit_hash_ver = cur_commit_hash_ver.replace("linux","")
    if "-" in cur_commit_hash_ver:
        cur_commit_hash_ver = cur_commit_hash_ver[:cur_commit_hash_ver.index("-")]

    return cur_commit_hash_ver