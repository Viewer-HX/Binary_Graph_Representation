## Content
This folder contains 
- the documents on how to generate XDA-based node embeddings for (sliced) subgraph;

## Usage
- In the subgraph case:
	- Run script `python transfer_assembly_block_to_machine_code_subcfg_judged.py` or `python transfer_assembly_block_to_machine_code_subcfg_security.py` to generate machine code for each block, 
	- Then leverage XDA approach to generate embeddings for each block, 
	- Finally run script `python transfer_subgraph_to_embed_npz.py` to generate unified npz format subgraph, which could be directly used for GNN based detection;
		
- In the sliced subgraph case: 
	- Run script `python transfer_assembly_block_to_machine_code_slicedcfg.py` or `python transfer_assembly_block_to_machine_code_slicedcfg_security.py` to generate machine code of each block,
	- Then leverage XDA approach to generate embeddings for each block,
	- Finally run script `python transfer_subgraph_to_embed_npz.py` to generate unified npz format subgraph, which could be directly used for GNN based detection.
	
## Detailed description:

- `transfer_assembly_block_to_machine_code_subcfg_judged.py`
	- (For the *judged patch dataset*) This script converts the assembly block of patched and unpatched subgraph (CFG) into machine codes.
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related subgraph information
		"binary_subgraph_success_info": the filename which contains the status of subgraph successful generation  
		"subgraph_success_tag": the flag of subgraph successful generation
		"patch_meta": the meta information filename of commit message
		"*_commits_dir": the absolute path of patch related commit message directory (security/ non-security)
		"block_byte_dir": the absolute path of binary code for each block directory 
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```
		
- `transfer_assembly_block_to_machine_code_subcfg_security.py`
	- (For the *CVE security patch dataset*) This script converts the assembly block of patched and unpatched subgraph (CFG) into machine codes.
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related subgraph information
		"binary_subgraph_success_info": the filename which contains the status of subgraph successful generation  
		"subgraph_success_tag": the flag of subgraph successful generation
		"patch_meta": the meta information filename of commit message
		"*_commits_dir": the absolute path of patch related commit message directory (security)
		"block_byte_dir": the absolute path of binary code for each block directory 
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```
		
- `transfer_assembly_block_to_machine_code_slicedcfg_judged.py`
	- (For the *judged patch dataset*) This script converts the assembly block of patched and unpatched sliced subgraph (CFG, CDG, DDG) into machine codes.
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related sliced subgraph information
		"binary_subgraph_success_info": the filename which contains the status of sliced subgraph successful generation  
		"subgraph_success_tag": the flag of sliced subgraph successful generation
		"patch_meta": the meta information filename of commit message
		"*_commits_dir": the absolute path of patch related commit message directory (security/ non-security)
		"block_byte_dir": the absolute path of binary code for each block directory 
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```

- `transfer_assembly_block_to_machine_code_slicedcfg_security.py`
	- (For the *CVE security patch dataset*) This script converts the assembly block of patched and unpatched sliced subgraph  (CFG, CDG, DDG)  into machine codes.
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related sliced subgraph information
		"binary_subgraph_success_info": the filename which contains the status of sliced subgraph successful generation  
		"subgraph_success_tag": the flag of sliced subgraph successful generation
		"patch_meta": the meta information filename of commit message
		"*_commits_dir": the absolute path of patch related commit message directory (security)
		"block_byte_dir": the absolute path of binary code for each block directory 
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```
- transfer_subgraph_to_embed_npz.py
	- This script converts the format subgraph, the generated XDA-based node embeddings into unified *npz* format combining with the block embeddings.
	- The configuration in script:
		```
		"sub_graph_format_dir": the absolute path of stored format subgraph directory 
		"block_embedding_dir": the absolute path of generated XDA-based block embeddings directory 
		"subgraph_npz_dir": the absolute path of unified npz directory
		```
		
- utility.py
	- This script provides the basic file operation, execute external command file and jsonObject being converting to each other, etc.
		
