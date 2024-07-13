import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
import csv
import bct
from pyvis.network import Network
import webbrowser
import time


combined_graph = nx.MultiDiGraph()


# clean_graph
# malicious_graph


#
# def convert_datasets(f):
#     print("Begin Converting Datasets")
#     data_frame = pd.read_csv(f, usecols=["duration", "src_ip", "dst_ip", "src_bytes", "dst_bytes", "label"])
#     data_frame.to_csv(f"assets/extracted_data.csv", index=False)


def import_network(file):
    network_data = {}
    # print(network_data)
    try:
        with open(file, newline='') as csvfile:
            source_data = csv.reader(csvfile, delimiter=',')
            header = next(source_data)

            for row in source_data:
                print(row)
                print("ND : ", network_data)
                src_ip = row[0]
                dst_ip = row[1]
                src_bytes = 0 if (row[3] == '-' or row[3] == '') else float(row[3])
                dst_bytes = 0 if (row[4] == '-' or row[4] == '') else float(row[4])
                label = row[5]

                # Add/update edges in the dictionary
                if (src_ip, dst_ip) not in network_data:
                    network_data[(src_ip, dst_ip)] = {"bytes": src_bytes, "label": label}
                else:
                    network_data[(src_ip, dst_ip)]["bytes"] += src_bytes

                # Add reverse edge (dst_ip -> src_ip)
                if (dst_ip, src_ip) not in network_data:
                    network_data[(dst_ip, src_ip)] = {"bytes": dst_bytes, "label": label}
                else:
                    network_data[(dst_ip, src_ip)]["bytes"] += dst_bytes

        # print(network_data)


    except FileNotFoundError:
        print(f"Error: File '{file}' not found.")
        return []

    print("Sending edgelist")
    edgeList = []
    for (src, dst), attributes in network_data.items():
        # print(src, dst, attributes)
        edgeList.append((src, dst, attributes["bytes"]))
    return edgeList

def metric_calculations():
    print("Begin Metric Calculations")


def create_network_edgelist():
    # clean_edgeList1 = import_network('assets/datasets/clean/clean_honeypot_4-1.csv')
    # clean_edgeList2 = import_network('assets/datasets/clean/clean_honeypot_5-1.csv')
    clean_edgeList3 = import_network('assets/datasets/clean/clean_honeypot_7-1.csv')
    # malicious_edgeList1 = import_network('assets/datasets/malicious/Malware_44-1.csv')
    # malicious_edgeList2 = import_network('assets/datasets/malicious/Malware_20-1.csv')
    # malicious_edgeList3 = import_network('assets/datasets/malicious/Malware_21-1.csv')

    # combined_graph.add_weighted_edges_from(clean_edgeList1)
    # print(combined_graph)
    # combined_graph.add_weighted_edges_from(clean_edgeList2)
    # print(combined_graph)

    combined_graph.add_weighted_edges_from(clean_edgeList3)
    print(combined_graph)
    # combined_graph.add_weighted_edges_from(malicious_edgeList1, weight="bytes")
    # print(combined_graph)
    # combined_graph.add_weighted_edges_from(malicious_edgeList2, weight="bytes")
    # print(combined_graph)
    # combined_graph.add_weighted_edges_from(malicious_edgeList3, weight="bytes")
    # print(combined_graph)
    #
    # combined_graph.add_weighted_edges_from(malicious_edgeList1, weight="bytes")
    # print(combined_graph)
    # combined_graph.add_weighted_edges_from(malicious_edgeList2, weight="bytes")
    # print(combined_graph)
    # combined_graph.add_weighted_edges_from(malicious_edgeList3, weight="bytes")
    # print(combined_graph)


def draw_normal_graph():
    print("Drawing Normal Graph")
    # MatPlotLib Settings
    limits = plt.axis("off")

    # nx.draw(combined_graph, with_labels=True)
    nx.draw_networkx(combined_graph, with_labels=True)
    plt.show()


def draw_pyvis():
    # Visualize
    print("Converting Graph to interactive Pyvis WebPage")

    net = Network(
            directed=True,
            select_menu=True,  # Show part 1 in the plot (optional)
            filter_menu=True,  # Show part 2 in the plot (optional)
            )
    net.show_buttons()  # Show part 3 in the plot (optional)
    net.from_nx(combined_graph)  # Create directly from nx graph
    net.show('clean_4-2.html', notebook=False)


def draw_Gephi():
    print("Converting Graph to .gexf  for Gephi Imports")
    # nx.write_gexf(combined_graph, "clean_3_combined.gexf")
    nx.write_gexf(combined_graph, "assets/gephi/malicious-3.gexf")


if __name__ == '__main__':
    start_time = time.time()

    # Choose Datasets and Create EdgeList
    create_network_edgelist()

    # Choose Method Of Graph Presentation
    draw_normal_graph()

    # draw_pyvis()

    # draw_Gephi()

    print("Finish Drawing")

    # Metrics
    # https://github.com/aestrivex/bctpy/blob/master/docs/bct.rst
    # brain connectivity toolkit is more useful than networkx on directed graphs
    # kindly calculate metrics with bct rather than nx
    metric_calculations()
    print("--- %s seconds ---" % (time.time() - start_time))
