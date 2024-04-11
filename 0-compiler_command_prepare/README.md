## Content
This folder contains
- the documents on how to construct built container environment and build log;
- the scripts on parsing the build logs to compiler commands.

## Usage:
- Building the container environment according to instructions in `Software_build_process.txt` and `Linux_kernel_doc.txt`;
- Run the script `python parse_build_logs_kernel.py` and `python parse_build_logs_software.py` to parse the build logs.
	
## Detailed description: 
- `Software_build_process.txt`

	- The building process and built container environment constructing for popular github repositories.
		
- `Linux_kernel_doc.txt`

	- The building help documents for multiple Linux kernel versions.
		
- `parse_build_logs_kernel.py`

	- The python script for Linux kernel build log parsing.	

	- The configuration in script:
		```
		"build_log_dir": the directory of original build log
		"clang_log_prefix_name": the prefix filename of clang's build log
		"gcc_log_prefix_name": the prefix filename of gcc's build log
		"clang_compiler_cmd_dir": the directory of clang compiler commands
		"gcc_compiler_cmd_dir": the directory of gcc compiler commands
		```

- `parse_build_logs_software.py`

	- The python script for popular software build log parsing.

	- The configuration in script:
		```
		"build_log_dir": the directory of original build log
		"clang_log_prefix_name": the prefix filename of clang's build log
		"gcc_log_prefix_name": the prefix filename of gcc's build log
		"clang_compiler_cmd_dir": the directory of clang compiler commands
		"gcc_compiler_cmd_dir": the directory of gcc compiler commands
		```
