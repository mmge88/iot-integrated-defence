"""
This module contains network object and relevant functions.
@author: Mengmeng Ge
"""

from Node import *
import copy

class network(object):
    """
    Create network object.
    """
    def __init__(self):
        #Initialize node list
        self.nodes = []
        #Initialize start and end points
        self.s = None
        self.e = None
        #Initialize subnets which contain each node's subnet
        self.subnets = []
        #Initialize vulnerability list which contains all node vulnerabilities
        self.vuls = []
        #Store the maximum depth
        self.max_depth = 0
        #Store the maximum hop
        self.max_hop = 0


def copyNet(net):
    """
    Copy the network to a network.
    """
    
    temp = network()
    temp = copy.deepcopy(net)
    
    return temp

def constructSE(net):
    """
    Set the start and end in the network.
    """

    net.s = node('S-')
    net.e = node('E-')
        
    for n in net.nodes:
        if n.isStart:
            net.s.con.append(n)
        if n.isEnd:
            n.con.append(net.e)

          
def connectOneWay(node1, node2):
    """
    Connect node1 to node2 in the network.
    """
    #no self connection
    if node1 is node2:
        return None
    #connect node1 to node2
    if (node2 not in node1.con):
        node1.con.append(node2)    
        #print(node1.name, node2.name)


def connectTwoWays(node1, node2):
    """
    Connect node1 with node2 in the network.
    """
    #no self connection
    if node1 is node2:
        return None
    #create connections
    if (node2 not in node1.con):
        node1.con.append(node2)
    if (node1 not in node2.con):
        node2.con.append(node1)
    return None

def removeNodeFromList(node, con_list):
    """
    Remove node from the original connection list
    """
    for i in con_list:
        if i.name == node.name:
            con_list.remove(i)
            break
    return None

def disconnectOneWay(node1, node2):
    """
    Disconnect node1 with node2 in the network
    """
    names = [i.name for i in node1.con]
    if node2.name in names:
        #print(node2.name, names)
        removeNodeFromList(node2, node1.con)
    return None

def disconnectTwoWays(node1, node2):
    """
    Disconnect node1 and node2 in the network.
    """
    if node2 in node1.con:
        node1.con.remove(node2)   
    if node1 in node2.con:
        node2.con.remove(node1)  
    return None

def printNet(net):
    """
    Print network.
    """   
    for node in net.nodes:
        print(node.name+":", node.type)
        print("connect:",)
        for conNode in node.con:
            print(conNode.name)
        print("-----------------------------")
    return None


def printNetWithVul(net):
    """
    Print network with vulnerabilities.
    """   
    for node in net.nodes:
        #print(node.name+":", node.type, ",", node.sec)
        print(node.name+":", node.type, node.comp, node.critical, node.id)
        print("connect:",)
        for conNode in node.con:
            if conNode.name == 'S-' or conNode.name == 'E-':
                print(conNode.name)
            else:
                print(conNode.name, conNode.id)      

        print("------------------------------")

    return None

def computeNeighbors(net):
    """
    Compute 1-hop neighbors.
    Do not exclude redundant neighbor nodes yet.
    """
    neighbor_list = []
    for node in net.nodes:
        for conNode in node.con:
            if conNode.critical == True:
                neighbor_list.append(node)
    return neighbor_list
