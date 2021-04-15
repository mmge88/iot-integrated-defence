"""
This module conducts security analysis.

@author: Mengmeng Ge
"""

from attackGraph import *
from attackTree import *
from harm import *
from SDIoTGen import *
import subprocess
import os
import re
import math
from random import shuffle, uniform, expovariate
import numpy as np


#---------------------------------------------------------------------------------------------------
#Compute compromise rate for lower layer (AT); MTTC (path level) and MTTSF for upper layer (AG)
#We only consider two cases: 
#1) one vulnerability for each node 
#2) multiple vulnerabilities for one node:
#   only ADN or OR, which means the attacker need to use all vulnerabilities or any one of them
#---------------------------------------------------------------------------------------------------

def computeNodeMTTC(node):
    count = 0
    MTTC = 0
    flag = False

    if node.type == True:
        node.comp = True
        count += 1
        if node.critical == True:
            flag = True
        MTTC = 1.0/node.val
    else:
        #node.comp = True
        #Introduce error range for decoy node
        error_value = uniform(-0.05, 0.05)
        pro = node.pro + error_value
        if pro > 1.0:
            pro = 1.0 
        MTTC = (1.0/node.val) * pro
    #print(node.name, node.type, node.val, MTTC, flag)
    return MTTC, count, flag

#---------------------------------------------------------------------------------------------------
#Compute MTTSF used in GA
#---------------------------------------------------------------------------------------------------

def computeMTTSF(harm, net, cflag):
    """
    Compute MTTSF based on the attacker's intelligence.
    Used for computing optimal topology via GA.
    Assume IDS has 100% accuracy.
    """
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath) #Attacker randomly picks one entry point at a time
    #harm.model.printPath()
    #print("number of attack paths:", len(harm.model.allpath))
    MTTSF = 0
    break_flag = False
    
    totalCount = 0
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, count, flag = computeNodeMTTC(node) 
                    MTTSF += MTTC
                    if node.type == True:
                        totalCount += count
                    #print(float(totalCount/totalNo))
                    
                    if float(totalCount/totalNo) >= cflag or flag == True:
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
    
    return MTTSF 

#---------------------------------------------------------------------------------------------------
#Compute MTTSF in shuffling
#----------------------------------------------------------------------------------------------------

def computeCompNodes(node, detect_pro):
    """
    Simulate attacker's behavior.
    Generate the compromised nodes
    """
    flag = False #SF2
    detect_pro = 1.0 #Reflect real compromised nodes by the attacker
    #print("Compromised node: ", node.name, node.type, node.val)
    #Critical node can be always detected
    if node.type == True:
        node.comp = True
        if node.critical == True:
            flag = True
        MTTC = (1.0/node.val) * node.pro - node.prev_comp
    else:
        #node.comp = True
        #Introduce error range for decoy node
        error_value = uniform(-0.05, 0.05)
        pro = node.pro + error_value
        MTTC = (1.0/node.val) * pro * detect_pro
    #print("MTTC: ", MTTC)  
    return MTTC, flag 

def checkNeighbors(compNodes, neighbor_list):
    compNo = 0
    for node in compNodes:
        for neighbor in neighbor_list:
            if node.name == "ag_"+neighbor.name:
                compNo += 1
    #print("Number of compromised neighbors: ", compNo)
    return compNo

def assignCompNodeInNet(decoy_net, attack_node):
    for node in decoy_net.nodes:
        if attack_node.name == "ag_"+node.name:
            #print("Assign compromised node in original net: ", node.name, attack_node.name)
            node.comp = True
    return None

def modifyCompNodeInNet(decoy_net, attack_node, left_time):
    
    for node in decoy_net.nodes:
        if attack_node.name == "ag_"+node.name:
            #print("Assign compromised node in original net: ", node.name, attack_node.name)
            
            node.prev_comp = node.prev_comp + left_time
    return None

def computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo):
    """
    Zero false positive and false negative by IDS.
    """
    dividend1 = len(compNodes)
    divisor1 = totalNo
    value1 = dividend1/divisor1
    
    dividend2 = compNeighborNo 
    divisor2 = neighborNo
    value2 = dividend2/divisor2
    return value1, value2
    
def computeIDSRateMTTSF(detect_pro, compNodes, totalNo):
   
    dividend = len(compNodes) 
    divisor = totalNo
    value = dividend/divisor   
    return value 

def computeSSL_Interval(harm, net, decoy_net, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes):
    """
    Compute system security level for adaptive shuffling.
    """
    
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:",)) 

    totalTime = 0 #Total time between each shuffling
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
    #print("Neighbor list: ", [i.name for i in neighbor_list])
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    #Simulate attacker's behavior
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    if node.type == True:
                        compNodes.append(node)
                        assignCompNodeInNet(decoy_net, node)
                        
                    totalTime += MTTC
                    
                    #print("SF1: ", float(len(compNodes)/totalNo))
                    #print("SF2: ", flag)
                    compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                    #Incorporate IDS accuracy
                    value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                    #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                    SSL =  w1 * value1 + w2 * value2
                    #print("SSL: ", SSL)
                    #Exit inner loop
                    if value1 >= cflag or flag == True:
                        SSL = 1.0
                        break_flag = True
                        break
                    elif (SSL - previous_ssl) > thre_check:
                        break_flag = True
                        break
                        
        #Exit outer loop
        if break_flag == True:
            break
    #print("MTTC:", totalTime)
    return SSL, totalTime, compNodes, decoy_net

def computeSSL_FixedInterval(harm, net, decoy_net, thre_check, cflag, detect_pro, w1, w2, previous_ssl, compNodes, delay):
    """
    Compute system security level for hybrid shuffling: mix of adaptive and fixed interval.
    """
    
    totalNo = len(net.nodes)
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:",)) 
    
    #print("==============================================================================")
    totalTime = 0
    SSL = 0.0
    neighbor_list = computeNeighbors(net)
    neighborNo = len(neighbor_list)
    #print("Neighbor list: ", [i.name for i in neighbor_list])
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    #print(node.name, node.val)
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    
                    #Calculate the previous total compromise time
                    previousTotalTime = totalTime - MTTC
                    interval_left = delay - previousTotalTime
                    #print("Accumulated MTTC:", totalTime)
                    
                    if totalTime < delay:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                    
                        #print("SF1: ", float(len(compNodes)/totalNo))
                        #print("SF2: ", flag)
                        compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                        value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                        #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                        SSL =  w1 * value1 + w2 * value2
                        #print("SSL when compromise time smaller than interval: ", SSL)
                        #Exit inner loop
                        if value1 >= cflag or flag == True:
                            SSL = 1.0
                            break_flag = True
                            break
                        elif (SSL - previous_ssl) > thre_check:
                            break_flag = True
                            break
                    elif totalTime == delay:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        break_flag = True
                        
                        #print("SF1: ", float(len(compNodes)/totalNo))
                        #print("SF2: ", flag)
                        compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                        value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                        #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                        SSL =  w1 * value1 + w2 * value2
                        #print("SSL when compromise time equals to interval: ", SSL)
                        if value1 >= cflag or flag == True:
                            SSL = 1.0
                        break
                    else:
                        #Shuffle when under attack
                        if node.type == True:
                            #Change the previous compromise time
                            modifyCompNodeInNet(decoy_net, node, interval_left)
                        totalTime = delay
                        break_flag = True
                        
                        #print("SF1: ", float(len(compNodes)/totalNo))
                        #print("SF2: ", flag)
                        compNeighborNo = checkNeighbors(compNodes, neighbor_list)
                        value1, value2 = computeIDSRateSSL(detect_pro, compNodes, totalNo, compNeighborNo, neighborNo)
                        #SSL = w1 * (len(compNodes)/totalNo) + w2 * (compNeighborNo/neighborNo)
                        SSL =  w1 * value1 + w2 * value2
                        #print("SSL when compromise time larger than interval: ", SSL)
                        if value1 >= cflag or flag == True:
                            SSL = 1.0
                        break    
                        
        #Exit outer loop
        if break_flag == True:
            break
    #print("MTTC:", totalTime)
    #print("SSL:", SSL)
    return SSL, totalTime, compNodes, decoy_net

def computeMTTSF_Baseline(harm, net, attack_net, cflag, detect_pro, compNodes):
    """
    Compute system security level for baseline scheme.
    """
    totalNo = len(net.nodes)
    totalCount = 0
    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", ) 
    
    totalTime = 0
    security_failure = False
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    print(node.name, node.val, node.type)
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    totalCount += 1
                    
                    print("Accumulated MTTC:", totalTime)
                    if node.type == True:
                        compNodes.append(node)
                        assignCompNodeInNet(attack_net, node)
                    ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)

                    #Exit inner loop 
                    if ratioIDS >= cflag or flag == True:
                        print("Failure condition: ", ratioIDS, flag)
                        security_failure = True
                        break_flag = True
                        break

        #Exit outer loop
        if break_flag == True:
            break
       
    return totalTime, compNodes, attack_net, security_failure

def computeMTTSF_Interval(harm, net, decoy_net, interval_check, cflag, detect_pro, compNodes, security_failure):
    """
    Compute system security level for fixed interval shuffling.
    """
    totalNo = len(net.nodes)

    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", ) 
    
    
    totalTime = 0
    previousTotalTime = 0
    
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    
                    #Calculate the previous total compromise time
                    previousTotalTime = totalTime - MTTC
                    interval_left = interval_check - previousTotalTime
                    #print("Accumulated MTTC:", totalTime)
                    
                    if totalTime < interval_check:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #Exit inner loop 
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                            break_flag = True
                            break
                    elif totalTime == interval_check:
                        #Shuffle
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        break_flag = True
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #End
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                        break
                    else:
                        #Shuffle when under attack
                        if node.type == True:
                            #Change the previous compromise time
                            modifyCompNodeInNet(decoy_net, node, interval_left)
                        totalTime = interval_check
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
       
    return totalTime, compNodes, decoy_net, security_failure

def computeMTTSF_RandomInterval(harm, net, decoy_net, interval_mean, cflag, detect_pro, compNodes, security_failure):
    """
    Compute system security level for random interval shuffling.
    """
    totalNo = len(net.nodes)

    #print(totalNo)
    #Calculate the MTTC for each node on the attack path
    harm.model.calcMTTC()
    shuffle(harm.model.allpath)  
    #harm.model.printPath()
    #print("number of attack paths:", ) 
    
    
    totalTime = 0
    previousTotalTime = 0
    
    interval_check = expovariate(1.0/interval_mean)
    #print(interval_check)
    
    break_flag = False
    for path in harm.model.allpath:
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0 and node.comp == False:
                    MTTC, flag = computeCompNodes(node, detect_pro) 
                    totalTime += MTTC
                    
                    previousTotalTime = totalTime - MTTC
                    interval_left = interval_check - previousTotalTime
                    #print("Accumulated MTTC:", totalTime)
                    if totalTime < interval_check:
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #Exit inner loop
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                            break_flag = True
                            break
                    elif totalTime == interval_check:
                        #Shuffle
                        if node.type == True:
                            compNodes.append(node)
                            assignCompNodeInNet(decoy_net, node)
                        break_flag = True
                        ratioIDS = computeIDSRateMTTSF(detect_pro, compNodes, totalNo)
                        #End
                        if ratioIDS >= cflag or flag == True:
                            security_failure = True
                        break
                    else:
                        #Shuffle when under attack
                        if node.type == True:
                            #Change the previous compromise time
                            modifyCompNodeInNet(decoy_net, node, interval_left)
                        totalTime = interval_check
                        break_flag = True
                        break
                    
        #Exit outer loop
        if break_flag == True:
            break
       
    return totalTime, compNodes, decoy_net, security_failure
