## Content
This folder contains 
- the documents on how to extract subgraph (CFG) and sliced subgraph (CFG, CDG, DDG);
- the scripts on parsing stored subgraphs into format output.

## Usage:
- To extract subcfg information, 
	- Run script `python extract_patched_code_snippets_and_sub_graph.py` to extract subgraph (CFG) information, and then run script `python extract_patched_sub_graph_format_output.py` to convert the subgraph into format output;
- To extract sliced subcfg information, 
	- Run script `python extract_patched_slicing_info.py` to extract sliced subgraph information, and then run script `python extract_patched_sliced_sub_graph_format_output.py` to convert the sliced subgraph into format output;
- Currently, to use `Angr` modules, one may have to `workon angr` to swith to angr's `virtualenv`;

## Detailed description:
- `extract_patched_code_snippets_and_sub_graph.py`
	- This script provides the following functions:
		- disassembles the patched and unpatched binary (.o) files via *angr* and
		- then extracts patched and unpatched sub CFG, and patch related code snippets.
	- The configuration in script:
		```
		"commits_dir": the absolute path of patch related commit message directory (security/ non-security) 
		"patch_meta": the meta information filename of commit message
		"patched_funcs_assembly_info": the filename of patched assembly instruction information  
		"binary_subgraph_success_info": the prefix filename of patched subgraph information
		"timeout_commits": the commit messages which cause timeout when generating CFG
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```

- `extract_patched_sub_graph_format_output.py`
	- This script converts the stored patched and unpatched subgraph into formatting output
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related subgraph information
		"binary_subgraph_success_info": the filename which contains the status of subgraph successful generation 
		"subgraph_success_tag": the flag of subgraph successful generation
		"sub_graph_format_dir": the absolute path of format subgraph output directory
		"*_commits_dir": the absolute path of patch related subgraph directory (security/ non-security) 
		"patch_meta": the meta information filename of commit message
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```			
	- The format subgraph output (for *opcode one-hot encoding*)
		```
		#edge information
		<node_idx, node_idx, patch_tag( 0 for unpatched, 1 for patched)>
		===========================
		#node information
		<node_idx, [opcodes], patch_tag( 0 for unpatched, 1 for patched)>
		(0,1,0)
		(0,1,1)
		===========================
		(1,add,pop,ret,0)
		(0,push,mov,sub,mov,mov,mov,mov,mov,call,0)
		(1,add,pop,ret,1)
		(0,push,mov,sub,mov,mov,mov,mov,mov,call,1)
		```

- `extract_patched_slicing_info.py`
	- This script provides the following functions:
		- disassembles the patched and unpatched binary (.o) files via *angr*;
		- then extracts patched and unpatched sub CFG, CDG, DDG, slicing code snippets.
	- The configuration in script:
		```
		"commits_dir": the absolute path of patch related commit message directory (security/ non-security) 
		"patch_meta": the meta information filename of commit message
		"patched_funcs_assembly_info": the filename of patched assembly instruction information  
		"binary_subgraph_success_info": the prefix filename of patched subgraph information
		"timeout_commits": the commit messages which cause timeout when generating CFG
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```

- `extract_patched_sliced_sub_graph_format_output.py`
	- This script converts the stored patched and unpatched sliced subgraph into formatting output
	- The configuration in script:
		```
		"sliced_sub_graph_format_dir": the absolute path of format sliced subgraph output directory
		"patched_sliced_subgraph_prefix": the prefix filename of stored patch related sliced subgraph information
		"binary_subgraph_success_info": the filename which contains the status of sliced subgraph successful generation 
		"slicing_success_tag": the flag of sliced subgraph successful generation
		"*_commits_dir": the absolute path of patch related subgraph directory (security/ non-security) 
		"patch_meta": the meta information filename of commit message
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```
	- The format sliced subgraph output (for *opcode one-hot encoding*)
		```
		#edge information
		<node_idx, node_idx, edge_type( CFG | CDG | DDG ), patch_tag( 0 for unpatched, 1 for patched)>
		===========================
		#node information
		<node_idx, [opcodes], patch_tag( 0 for unpatched, 1 for patched)>
		(0,2,CFG,-1)
		(0,2,CFG,1)
		(0,2,DDG,-1)
		(0,2,DDG,1)
		===========================
		(2,mov,mov,add,mov,mov,leave,ret,-1)
		(0,push,mov,sub,call,-1)
		(2,mov,mov,add,mov,mov,leave,ret,1)
		(0,push,mov,sub,call,1)
		```
		

		
- utility.py
	- This script provides the basic file operation, execute external command file and jsonObject being converting to each other, etc.
		
