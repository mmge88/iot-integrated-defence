'''
This module provides random shuffling algorithm for computing network topology using in MTD. 

@author: Mengmeng Ge
'''

import warnings
import copy
import math
from SDIoTGen import *
from SecurityEvaluator import *
from random import uniform

def checkConnection(iot, decoy):
    for node in iot.con:
        if node.name == decoy.name:
            return 1
    return 0

def randomShuffling(decoy_net, threshold_pro):
    """
    The comparison between the randomly generated probability and threshold:
    As long as it is larger, add if no connection or remove if connection exists.
    Real node type: True
    Decoy node type: emulated or real
    """
    shuffled_net = copyNet(decoy_net)
    cost = 0
    
    #Change connections from real IoT nodes to decoy nodes
    for node1 in shuffled_net.nodes:
        if node1.type == True and node1.name.startswith("server") == False:
            for node2 in shuffled_net.nodes:
                if node2.type == "emulated" or node2.type == "real":
                    random_pro = uniform(0, 1)
                    #Add or remove connection 
                    if random_pro > threshold_pro:
                        #print(node1.name, node2.name)
                        #print("Add or remove connection based probability: ", random_pro, node1.name, node2.name)
                        if checkConnection(node1, node2) == 0:
                            connectOneWay(node1, node2)
                        else:
                            disconnectOneWay(node1, node2)
                        cost += 1
    
    #Change connections between real IoT nodes
    for node1 in shuffled_net.nodes:
        if node1.type == True and node1.name.startswith("server") == False:
            for node2 in shuffled_net.nodes:
                if node2.type == True and node2.name.startswith("server") == False and node1.name != node2.name:
                    random_pro = uniform(0, 1)
                    #Add or remove connection 
                    if random_pro > threshold_pro:
                        #print(node1.name, node2.name)
                        #print("Add or remove connection based probability: ", random_pro, node1.name, node2.name)
                        if checkConnection(node1, node2) == 0:
                            connectOneWay(node1, node2)
                        else:
                            disconnectOneWay(node1, node2)
                        cost += 1  
    #print(cost)
    return shuffled_net, cost

def randomAddReal(decoy_net, threshold_pro, out_degree, maxLength, totalNodes):

    shuffled_net = copyNet(decoy_net)

    #Change connections from real IoT nodes to decoy nodes
    for node1 in shuffled_net.nodes:
        if node1.type == True and node1.name.startswith("server") == False:
            for node2 in shuffled_net.nodes:
                if node2.type == "emulated" or node2.type == "real":
                    random_pro = uniform(0, 1)
                    #Add or remove connection 
                    if random_pro > threshold_pro:
                        #print(node1.name, node2.name)
                        #print("Add or remove connection based probability: ", random_pro, node1.name, node2.name)
                        if checkConnection(node1, node2) == 0:
                            connectOneWay(node1, node2)
    
    #Add connections between real IoT nodes
    for node1 in shuffled_net.nodes:
        if node1.type == True and node1.name.startswith("server") == False:
            for node2 in shuffled_net.nodes:
                if node2.type == True and node2.name.startswith("server") == False and node1.name != node2.name:
                    #Add connection from node1 to node2 
                    random_pro = uniform(0, 1)
                    #Add or remove connection 
                    #print("Max hop of node2:", node2.name, calcNodeHopsToTarget(node2, 0, 0))
                    if random_pro > threshold_pro:
                        if checkConnection(node1, node2) == 0 and len(node1.con) <= out_degree:
                            if totalNodes > 50:
                                if node2.calcNodeHopsToTarget(0, 0) <= maxLength and node1.subnet != node2.subnet:
                                    print("Connections", node1.name, node1.subnet, node2.name, node2.subnet)
                                    connectOneWay(node1, node2)
                            else:
                                connectOneWay(node1, node2)
                    else:
                        disconnectOneWay(node1, node2)
    
    return shuffled_net
