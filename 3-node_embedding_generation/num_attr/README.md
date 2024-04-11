## Content
This folder contains 
- the documents on how to generate numerical node embeddings for (sliced) subgraph;

## Usage
- In the subgraph case:
	- Run script `python extract_subcfg_judged_num_attr.py` or `python extract_subcfg_security_num_attr.py` to generate numerical block embedding, 
	- Then run script `python transfer_subgraph_to_num_npz.py` to generate unified npz format subgraph, which could be directly used for GNN based detection;
		
- In the sliced subgraph case:
	- Tun script `python extract_sliced_subcfg_judged_num_attr.py` or ` python extract_sliced_subcfg_security_num_attr.py` to generate numerical block embedding, 
	- Then run script `python transfer_subgraph_to_num_npz.py` to generate unified npz format subgraph, which could be directly used for GNN based detection;
	
## Detailed description:
- `extract_subcfg_judged_num_attr.py`
	- (For the *judged patch dataset*) This script extracts numerical attribute of each assembly block of subgraph (CFG);
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related subgraph information
		"binary_subgraph_success_info": the filename which contains the status of subgraph successful generation  
		"subgraph_success_tag": the flag of subgraph successful generation
		"*_commits_dir": the absolute path of patch related commit message directory (security/ non-security)
		"sub_graph_format_dir": the absolute path of stored format subgraph directory 
		"numerical_attribute_dir": the absolute path of generated numerical block embeddings directory
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```

- `extract_subcfg_security_num_attr.py`
	- (For the *CVE security patch dataset*) This script extracts numerical attribute of each assembly block of subgraph (CFG);
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related subgraph information
		"binary_subgraph_success_info": the filename which contains the status of subgraph successful generation  
		"subgraph_success_tag": the flag of subgraph successful generation
		"*_commits_dir": the absolute path of patch related commit message directory (security)
		"sub_graph_format_dir": the absolute path of stored format subgraph directory 
		"numerical_attribute_dir": the absolute path of generated numerical block embeddings directory
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```	
		
- `extract_sliced_subcfg_judged_num_attr.py`
	- (For the *judged patch dataset*) This script extracts numerical attribute of each assembly block of sliced subgraph (CFG, CDG, DDG);
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related sliced subgraph information
		"binary_subgraph_success_info": the filename which contains the status of sliced subgraph successful generation  
		"subgraph_success_tag": the flag of sliced subgraph successful generation
		"*_commits_dir": the absolute path of patch related commit message directory (security/ non-security)
		"sub_graph_format_dir": the absolute path of stored format sliced subgraph directory 
		"numerical_attribute_dir": the absolute path of generated numerical block embeddings directory
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```
		
	
- `extract_sliced_subcfg_security_num_attr.py`
	- (For the *CVE security patch dataset*) This script extracts numerical attribute of each assembly block of sliced subgraph (CFG, CDG, DDG).
	- The configuration in script:
		```
		"patched_subgraph_prefix": the prefix filename of stored patch related sliced subgraph information
		"binary_subgraph_success_info": the filename which contains the status of sliced subgraph successful generation  
		"subgraph_success_tag": the flag of sliced subgraph successful generation
		"*_commits_dir": the absolute path of patch related commit message directory (security)
		"sub_graph_format_dir": the absolute path of stored format sliced subgraph directory 
		"numerical_attribute_dir": the absolute path of generated numerical block embeddings directory
		"log_file_name": the relative path of the log file which recording the execution process of this script, which can be used for debugging
		```
	
- `transfer_subgraph_to_num_npz.py`
	- This script converts the format subgraph into unified *npz* format combining with the block embeddings;
	- The configuration in script:
		```
		"sub_graph_format_dir": the absolute path of stored format subgraph directory 
		"block_embedding_dir": the absolute path of generated block embeddings directory 
		"subgraph_npz_dir": the absolute path of unified npz directory
		```

- `utility.py`
	- This script provides the basic file operation, execute external command file and jsonObject being converting to each other, etc.
		
