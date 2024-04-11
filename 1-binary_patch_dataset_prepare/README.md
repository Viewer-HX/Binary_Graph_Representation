## Content
This folder contains 
- The scripts extract source code patch files and compile these files into binary files.
	
## Usage:

- In Linux kernel case:
	- Run script `python extract_patched_source_code_files_and_gen_ir_assembly_binary_files_kernel.py` to generate unpatched and patched binaries;
	
- In common software case:
	- Run script `python extract_patched_source_code_files_and_gen_ir_assembly_binary_files_software.py` to generate unpatched and patched binaries;
- Notice!!!
	- The two scripts `python extract_patched_source_code_files_and_gen_ir_assembly_binary_files_kernel.py` and `python extract_patched_source_code_files_and_gen_ir_assembly_binary_files_software.py` require the `goto-statement==1.2` modules, which can only be installed in `python 2.7`;
	
## Detailed description:	
- `extract_patched_source_code_files_and_gen_ir_assembly_binary_files_kernel.py`

	- This script provides the following functions:
		- extracts patched and unpatched source code files from patch related commit message;
		- compiles the source code files into LLVM IR files, assembly files and binary files via gcc and clang with different optimization levels;
		- for github kernel repository.
	- The configuration in script:
		```
		"commits_dir": the absolute path of patch related commit message directory (security/ non-security)  
		"temp_dir": the relative path of temp directory for github repository storage 
		"empty_project_list": the empty software list
		"compiler_option_dir": the relative path of compiler option directory
		"linux_clang_compiler_cmds_dir": the absolute path of clang compiler command directory for Linux kernel
		"linux_gcc_compiler_cmds_dir": the absolute path of gcc compiler command directory for Linux kernel
		"linux_all_commits_stat_info_filepath": the absolute path of the file containing all Linux kernel commit messages info in github
		"kernel_optimization_levels": the optimization levels
		```

- `extract_patched_source_code_files_and_gen_ir_assembly_binary_files_software.py`

	- This script provides the similar functions:
		- extracts patched and unpatched source code files from patch related commit message;
		- compiles the source code files into LLVM IR files, assembly files and binary files via gcc and clang with different optimization levels;
		- especially for common software;
	- The configuration in script:
		```
		"commits_dir": the absolute path of patch related commit message directory (security/ non-security) 
		"temp_dir": the relative path of temp directory for github repository storage 
		"empty_project_list": the empty software list
		"compiler_option_dir": the relative path of compiler option directory
		"software_clang_compiler_cmds_dir": the absolute path of clang compiler command directory for common software
		"software_gcc_compiler_cmds_dir": the absolute path of gcc compiler command directory for common software
		"software_optimization_levels": the optimization levels
		"built_projects": the built common software list
		```

- `github_commit_operations.py`
	- This script provides basic github commit lookup and statistic operation and commit message file parsing funciton
	
- `software_build_dependence_operation.py`
	- This script provides the build process for open source softwares, and also provide dependence path lookup methods for common source code files.
	
- `utility.py`
	- This script provides the basic file operation, execute external command file and jsonObject being converting to each other, etc.
