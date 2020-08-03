'''
This module provides a heuristic algorithm (i.e., maximise number of decoy paths for real IoT nodes) for computing suboptimal network topology used in MTD. 

@author: Mengmeng Ge
'''

import copy
import math
from SDIoTGen import *
from SecurityEvaluator import *
from random import *
from sortedcontainers.sortedlist import SortedList

def travelPath(conNode, dserver, path, allpath, oriNode):
     
    for v in conNode.con:
        #print(v.name)
        if v.inPath == 0: 
            
            #path.append(v.name) #Only append name
            v.inPath = 1

            #Recursively traverse the path until to the decoy server
            if v.name != dserver.name:                
                travelPath(v, dserver, path, allpath, oriNode)                            
            else:
                oriNode.num += 1
                #oriNode.current_hop += len(path)
                #allpath.append(path[:])
                
            #path.pop()
            v.inPath = 0
               
    return None

def travelNetAll(net, dserver): 
    allpath = []

    for node1 in net.nodes:
        if node1.type == True and node1.name.startswith("server") == False:
             #node1.current_hop = 0
             node1.num = 0
             node1.inPath = 1
             path = [node1.name]
             travelPath(node1, dserver, path, allpath, node1) 
             node1.inPath = 0
             del path
             #print(node1.name, node1.num)
    
    #print(allpath)
    return None

def getNameList(path):
    temp = []
    for n in path:
        temp.append(n.name)
    return temp

def returnNode(net, name):
    for n in net.nodes:
        if n.name == name:
            return n

def returnMax(sortedList):
    val = 0
    newList = []
    for i in sortedList:
        if i[1][0] >= val:
            newList.append(i[0])
            val = i[1][0]
    return newList

def returnMin(sortedList):
    val = sortedList[0][1][0]
    newList = []
    for i in sortedList:
        if i[1][0] <= val:
            newList.append(i[0])
            #val = i[1][0]
    return newList

def checkNodeNotInPath(con, newCon, allpath):
    for i in newCon[1]:
        if con in getNameList(allpath[i]):
            return False
    return True

def checkConnection(iot, decoy):
    for node in iot.con:
        if node.name == decoy.name:
            return 1
    return 0

def getDecoys(nodes, threshold_pro):
    nameList = []
    for node in nodes:
        if node.type == "emulated" or node.type == "real":
            nameList.append(node.name)
    
    random_pro = uniform(0, 1)
    if random_pro >= threshold_pro:
        l = [x for x in range(int(len(nameList)/2), len(nameList))]
        #print(l)
        num = choice(l)
    else:
        num = len(nameList)
    
    return sample(nameList, k=num)

def getDecoyServer(nodes):
    for node in nodes:
        if node.name.startswith("decoy_server") == True:
            #print(node.name)
            return node

def removeNodeWithMinAP(node):
    val = 0
    name = ""
    flag = False
    for conNode in node.con:
        if conNode.type == True and conNode.name.startswith("server") == False:
            print(conNode.name, conNode.num)
            if flag == False:
                val = conNode.num
                name = conNode.name
                flag = True
            else:
                if conNode.num < val:
                    val = conNode.num
                    name = conNode.name
        
    #print("Min AP:", name)
    
    for conNode in node.con:
        if conNode.name == name:
            disconnectOneWay(node, conNode)
            break
    """ 
    for conNode in node.con:
        print("Test: ", conNode.name)
    """
    return None
        
        
def getRealCon(node):
    num = 0
    for conNode in node.con:
        #print("Check connection to real nodes:", conNode.name)
        if conNode.type == True:
            num += 1
    #print(num)
    return num

def heuristicShuffling(decoy_net, threshold_pro, out_degree, maxLength):
    """
    Real node type: True
    Decoy node type: emulated or real
    """
    shuffled_net = copyNet(decoy_net)
    cost = 0
    
    # Change connection towards decoy nodes
    for node1 in shuffled_net.nodes:
        if node1.type == True and node1.name.startswith("server") == False: 
            decoys = getDecoys(shuffled_net.nodes, threshold_pro)
            #print("decoys: ", decoys)
            #print("current cons: ", getNameList(node1.con))
            for node2 in shuffled_net.nodes:
                if node2.name in decoys and checkConnection(node1, node2) == 0:
                    connectOneWay(node1, node2)
                    cost += 1
            for node3 in node1.con:
                if node3.name.find("decoy") > -1 and node3.name not in decoys:
                    disconnectOneWay(node1, node3)
                    cost += 1
            #print("new cons: ", getNameList(node1.con))
            del decoys
    
    travelNetAll(shuffled_net, getDecoyServer(shuffled_net.nodes))
    
    dic = {}
    for node1 in shuffled_net.nodes:
        if node1.name.startswith("server") == False and node1.name.find("decoy") < 0:
            dic[node1.name] = [node1.num, node1.hop]
            
    #print(dic)
    sortedList = sorted(dic.items(), key = lambda kv:(kv[1], kv[0]), reverse = True) # Max -> Min
    #print("all nodes with paths: ", sortedList) 
    reverseList = sorted(dic.items(), key = lambda kv:(kv[1], kv[0])) # Min -> Max
    del dic
    
    maxList = returnMax(sortedList)
    #print("nodes with max paths: ", maxList)
    
    minList = returnMin(reverseList)
    #print("nodes with min paths: ", minList)
    
    del sortedList
    del reverseList
    
    #flag = False
    for node1 in shuffled_net.nodes:
        if node1.name in minList:
            #print(node1.name)
            #print("current cons: ", getNameList(node1.con))
            for node2 in shuffled_net.nodes:
                
                if node2.name in maxList and checkConnection(node1, node2) == 0: #Check whether node2 is in node1's con
                    #Check out_degree for real IoT nodes
                    if getRealCon(node1) > out_degree:
                        #print("Remove connection for node1")
                        removeNodeWithMinAP(node1)
                        cost += 1
                    
                    #print("node2 in maxList:", node1.name, node2.name)
                    if getRealCon(node1) <= out_degree:
                        if len(decoy_net.nodes) < 50:
                            print("Add connection for node1")
                            connectOneWay(node1, node2)
                            cost += 1
                        else:
                            if node2.calcNodeHopsToTarget(0, 0) <= maxLength:
                                print("Add connection for node1")
                                connectOneWay(node1, node2)
                                cost += 1
                
        
    del maxList
    del minList
    return shuffled_net, cost
