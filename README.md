# Binary_Graph_Representation

This project will generate format subgraph information, according to commit message.  

The generated subgraph could be used for further GNN based detection.

## Operating Environment Requirements:
- The installation of Docker environment, please refer [Docker Installation](https://docs.docker.com/engine/install/ubuntu/);

- The installation of gcc and clang
	```
	apt install clang-<version> --install-suggests
	apt install build-essential
	for specific gcc version:
	apt install gcc-<version>
	```

- The installation of python 3 (3.8.10) and dependent modules
	```
	pip install goto-statement==1.2 (This can only be installed in python 2.7)
	pip install eventlet==0.29.1
	pip install func-timeout==4.3.5
	pip install numpy==1.20.1
	```

   For angr (9.0.4495) installation, please refer [Angr Installation](https://docs.angr.io/introductory-errata/install)

   For angr-utils (0.5.0) installation, please refer [Angr-tuils](https://github.com/axt/angr-utils)
	
## Usage:
- Following the step 0-3 in different folder to finish the format subgraph generation
	
### Step 0: 
- For preparation of software built environment, your can follow the instructions in folder `0-compiler_command_prepare/*`;
	
### Step 1: 
- For the generation of unpatched and patched binary, you can follow the instructions in folder `1-binary_patch_dataset_prepare/*`:
	```
	python extract_patched_source_code_files_and_gen_ir_assembly_binary_files.py 
	python extract_patched_source_code_files_and_gen_ir_assembly_binary_files_software.py
	```
		
		
### Step 2: 
- For the generation of unpatched and patched (sliced) subgrpah information, you can follow the instructions in folder `2-subgraph_extraction/*`:

   - For subgraph (CFG) information:
		```
		python extract_patched_code_snippets_and_sub_graph.py
		python extract_patched_sliced_sub_graph_format_output.py
		```

   - For sliced subgraph (CFG, CDG, DDG) information:
   		```
		python extract_patched_slicing_info.py 
		python extract_patched_sliced_sub_graph_format_output.py
		```
		
### Step 3: 
- For the generation of node embeddings, you can follow the instructions in folder `3-node_embedding_generation/*`:

   - For *XDA-based node embeddings generation*, follow instructions in folder `3-node_embedding_generation/XDA_based/*`:
			
		- subgraph (CFG):
			```
			python transfer_assembly_block_to_machine_code_subcfg_*.py
			python transfer_subgraph_to_embed_npz.py
			```
				
		- sliced subgraph (CFG, CDG, DDG)
			```
			python transfer_assembly_block_to_machine_code_slicedcfg_*.py
			python transfer_subgraph_to_embed_npz.py
			```

			
   - For *numerical node embeddings generation*, follow instructions in folder `3-node_embedding_generation/num_attr/*`:

		- subgraph (CFG): 
			```
			python extract_subcfg_*_num_attr.py
			python transfer_subgraph_to_num_npz.py
			```
				
		- sliced subgraph (CFG, CDG, DDG):
			```
			python extract_sliced_subcfg_*_num_attr.py
			python transfer_subgraph_to_num_npz.py
			```
			
