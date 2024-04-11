'''
    This script converts the format subgraph into unified npz format
    combining with the block embeddings
'''

import os, sys
import numpy as np

def main(subgraph_dir, embedding_dir, output_dir, tag):

    for filename in os.listdir(subgraph_dir):
        subgraph_path = subgraph_dir + "/" + filename
        edgesData = []
        node_flag = False
        nodesData = []
        try:

            with open(subgraph_path, "r") as fgraph:
                lines = fgraph.readlines()
                for line in lines:
                    line = line.strip()
                    if line == "===========================":
                        node_flag = True
                        continue
                    if node_flag:
                        block_info = line[1:-1].split(",")
                        block_idx = block_info[0]
                        patched = block_info[-1]
                        patch_tag = "before"
                        if patched == "1":
                            patch_tag = "after"

                        block_embedding_path = embedding_dir + "/" + filename \
                                               + "-" + patch_tag + "-block-" + block_idx + ".npy"
                        embeddings = np.load(block_embedding_path)
                        # print(embeddings.shape)
                        # print(temp.shape)
                        # print(temp2.shape)
                        # print(temp2)
                        # print(temp2.tolist())
                        node_info = []
                        node_info.append(int(block_idx))
                        node_info.append(int(patched))
                        node_info.append(embeddings)
                        nodesData.append(node_info)
                        # print(embeddings)
                        # print(node_info)
                        # print(nodesData)
                        # sys.exit(0)
                    else:
                        block_info = line[1:-1].split(",")
                        # print(block_info)
                        src_idx = block_info[0]
                        dst_idx = block_info[1]
                        edge_type = block_info[2].strip("'")
                        patched = block_info[-1]
                        # print(edge_type)
                        edge_info = []
                        edge_info.append(int(src_idx))
                        edge_info.append(int(dst_idx))
                        edge_info.append(edge_type)
                        edge_info.append(int(patched))
                        edgesData.append(edge_info)
            label = [int(tag)]
            label = np.array(label)
            # print(edgesData)
            # print(nodesData)
            npz_path = output_dir + "/" + filename + ".npz"
            edgesData = np.array(edgesData, dtype=object)
            nodesData = np.array(nodesData, dtype=object)
            np.savez(npz_path, edgesData=edgesData, nodesData=nodesData, label=label)
            # graph = np.load(npz_path, allow_pickle=True)
            # print(graph['edgesData'])
            # print(graph['nodesData'])
            # print(graph['label'])
            # sys.exit(0)
        except Exception as e:
            print(e)



if __name__ == '__main__':


    sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                           "subgraph/security_subgraph_format_output"
    block_embedding_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                          "block_num_attr/security_block_num_attr"
    subgraph_npz_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                           "subgraph_num_npz/security_subgraph_npz_output"
    main(sub_graph_format_dir, block_embedding_dir, subgraph_npz_dir, "1")

    sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                           "subgraph/security_judged_subgraph_format_output"
    block_embedding_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                          "block_num_attr/security_judged_block_num_attr"
    subgraph_npz_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                       "subgraph_num_npz/security_judged_subgraph_npz_output"
    main(sub_graph_format_dir, block_embedding_dir, subgraph_npz_dir, "1")

    sub_graph_format_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                           "subgraph/nonSecurity_subgraph_format_output"
    block_embedding_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                          "block_num_attr/nonSecurity_judged_block_num_attr"
    subgraph_npz_dir = "/home/binaryf/Binary_database/Crawler/subcfg/" \
                       "subgraph_num_npz/nonSecurity_subgraph_npz_output"
    main(sub_graph_format_dir, block_embedding_dir, subgraph_npz_dir, "0")
