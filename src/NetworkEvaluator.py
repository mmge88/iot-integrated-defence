"""
This module conducts performance analysis.
@author: Mengmeng Ge
"""

from attackGraph import *
from attackTree import *
from harm import *
import networkx as nx

"""
Use NetworkX to analyze network properties.
"""

def computeGraph(net):
    G = nx.Graph()
    for n in net.nodes:
        G.add_node(n.name)
        if len(n.parent) > 0:
            for c in n.parent: 
                G.add_edge(n.name,c.name)

    return G

def computeAveConnect(G):
    """
    Compute the average node connectivity of the network.
    """    
    print(G.nodes())
    print(G.edges())
    print(nx.average_node_connectivity(G))
    print(nx.degree(G,'Hub'))
    print(nx.degree(G,'Tablet'))
    
    return None

def computePathLength(G, source, target):
    """
    Compute the path length between two nodes.
    """
    hops = nx.shortest_path_length(G,source,target)
    
    return hops

def computeAveragePathLength(net, list):
    """
    Compute the path length between each pair of nodes.
    """
    hops = 0.0
    G = computeGraph(net)
    for node in list:
        hops += nx.shortest_path_length(G, node, '1')
    hops = hops / len(list) 
    return hops

def computeAveragePathLengthForNet(net):
    """
    Compute the path length between each pair of nodes.
    """
    hops = 0.0
    n = 0
    G = computeGraph(net)
    for node in net.nodes:
        if node.name != 'attacker' and len(node.parent) > 0:
            hops += nx.shortest_path_length(G, node.name, '1')
            #print(node.name, hops)
            n += 1
    hops = hops / n
    return hops

"""
Usability analysis.
"""

def computeHops(list, net):
    """
    Compute the average number of hops from nodes in specific area.
    """
    h = 0
    for node in net.nodes:
        for i in list:
            if node.name == i:
                if checkParent(node) == 0:
                    h = h + node.depth + 1
                break
     
    h = h / len(list)
    
    return h

def computeDegreeCentrality(net):
    
    return nx.degree_centrality(computeGraph(net))


def computeNetConnectivity(net):
    
    return nx.average_node_connectivity(computeGraph(net))

def chooseNodesOnDegreeCentrality(list, my_dic, frac):
    """
    Choose nodes based on the degree centrality.
    :param a list of isolated nodes.
    :param a dictionary of nodes' degree centrality values.
    :param a degree centrality value, if a node's value is larger than this, it should not be isolated in order to maintain the network connectivity.
    :returns a list of isolated nodes which should be isolated.
    """
    
    temp = []
    for node in list:    
        nm = node.name
        nm = nm[3:]
        for item in my_dic:
            if item == nm:
                #print(item, nm)
                #print(frac)
                #print(my_dic[item])
                if my_dic[item] < frac:
                    temp.append(node)
                    
    return temp
