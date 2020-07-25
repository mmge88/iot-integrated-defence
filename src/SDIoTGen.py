'''
This module provides an example IoT network and decoding of GA solutions to create the associated topology.  

@author: Mengmeng Ge
'''

from Node import *
from Network import *
from Vulnerability import *
from harm import *
from random import Random
from time import time
import ProblemFormulation as pf
from Metrics import *
from itertools import accumulate

#=================================================================================================
# Create real network 
#=================================================================================================

def add_conn(net):
    nodes_vlans = []
    for vlan in net.subnets:
        temp = []
        for node in net.nodes:
            if node.subnet == vlan:
                temp.append(node)
        nodes_vlans.append(temp)
    #print(nodes_vlans)
    
    #Add connections from other VLANs to VLAN4
    for node in nodes_vlans[3]:
        temp = nodes_vlans[0] + nodes_vlans[1] + nodes_vlans[2]
        for conNode in temp: 
            connectOneWay(conNode, node)
    
    """
    #Add connections from VLAN2 to VLAN3
    for node in nodes_vlans[1]:
        for conNode in nodes_vlans[2]:
            connectOneWay(node, conNode)
    """       
    return None


def add_vul(net):
    """
    Add vulnerabilities for real devices.
    """
    for node in net.nodes:
        if 'mri' in node.name or 'ct' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8308
            #Exploitability score: 6.8
            vul = vulNode("CVE-2018-8308")
            vul.createVul(node, 0.006, 1) 
        elif 'thermostat' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2013-4860
            vul = vulNode("CVE-2013-4860")
            vul.createVul(node, 0.006, 1)
        elif 'meter' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2017-9944
            #Exploitability score: 10.0
            vul = vulNode("CVE-2017-9944")
            vul.createVul(node, 0.042, 1)     
        elif 'camera' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-10660
            vul = vulNode("CVE-2018-10660")
            vul.createVul(node, 0.042, 1)     
        elif 'tv' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-4094
            #Exploitability score: 8.6
            vul = vulNode("CVE-2018-4094")
            vul.createVul(node, 0.012, 1)
        elif 'laptop' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8345
            #Exploitability score: 4.9
            vul = vulNode("CVE-2018-8345")
            vul.createVul(node, 0.004, 1, )     
        elif 'server' in node.name:
            #https://nvd.nist.gov/vuln/detail/CVE-2018-8273
            vul = vulNode("CVE-2018-8273")
            vul.createVul(node, 0.006, 1)                  

    return None

def createRealSDIoT(node_vlan_list):
    """
    An example SD-IoT network.
    :param a list of node names separated by VLAN
    """    
    net = network()
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            iot = realNode(j)
            iot.id = id
            iot.subnet = vlan
            #print(iot.subnet)
            if iot.subnet == 'vlan4':
                iot.critical = True
            net.nodes.append(iot)
            id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    #printNetWithVul(net)
    
    return net

def createRealSDIoTScale(node_vlan_list, scale):
    """
    An example SD-IoT network with addition of a subset of IoT nodes.
    :param a list of node names separated by VLAN
    """    
    net = network()
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            # Do not increase mri and ct
            if j in ['thermostat', 'meter', 'camera', 'tv', 'laptop']:
                for k in range(0, scale):
                    iot = realNode(j+str(k+1))
                    iot.id = id
                    iot.subnet = vlan
                    #print(iot.subnet)
                    if iot.subnet == 'vlan4':
                        iot.critical = True
                    net.nodes.append(iot)
                    id += 1
            else:
                iot = realNode(j)
                iot.id = id
                iot.subnet = vlan
                #print(iot.subnet)
                if iot.subnet == 'vlan4':
                    iot.critical = True
                net.nodes.append(iot)
                id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    printNetWithVul(net)
    
    return net

def createRealSDIoTScale2(node_vlan_list, scale):
    """
    An example SD-IoT network with addition of real IoT nodes.
    :param a list of node names separated by VLAN
    """    
    net = network()
    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        #print(temp)
        #Get nodes in a VLAN
        vlan = "vlan" + str(i+1)
        for j in temp:
            #print(j)
            # Do not increase mri and ct
            if j in ['thermostat', 'meter', 'camera', 'tv', 'laptop']:
                for k in range(0, scale):
                    iot = realNode(j+str(k+1))
                    iot.id = id
                    iot.subnet = vlan
                    #print(iot.subnet)
                    if iot.subnet == 'vlan4':
                        iot.critical = True
                    net.nodes.append(iot)
                    id += 1
            elif j in ['mri', 'ct']:
                for k in range(0, 2):
                    iot = realNode(j+str(k+1))
                    iot.id = id
                    iot.subnet = vlan
                    #print(iot.subnet)
                    if iot.subnet == 'vlan4':
                        iot.critical = True
                    net.nodes.append(iot)
                    id += 1
            else:
                iot = realNode(j)
                iot.id = id
                iot.subnet = vlan
                #print(iot.subnet)
                if iot.subnet == 'vlan4':
                    iot.critical = True
                net.nodes.append(iot)
                id += 1
        
        net.subnets.append(vlan)
    
    #Add vulnerabilities to real devices
    add_vul(net)
    add_conn(net)
    printNetWithVul(net)
    
    return net


def add_solution_set(solution_set):
    return solution_set['ct'], solution_set['camera'], solution_set['tv'], solution_set['server']

def getIoTNum(net):
    num = 0
    for node in net.nodes:
        if 'server' not in node.name:
            num += 1
    return num

#=================================================================================================
# Add attacker and create HARM
#=================================================================================================

def add_attacker(net):
    #Add attacker
    A = device('attacker')    
    A.setStart()
    for temp in net.nodes:
        
        #Set the real and decoy servers as targets
        if "server" in temp.name:
            #print("server", temp.name)
            temp.setEnd()
        else:
            #print("others", temp.name)
            A.con.append(temp)
    
    net.nodes.append(A)
    
    constructSE(net)

    return net

def constructHARM(net):
    #Create security model
    h = harm()
    
    #printNet(net)
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 1)
    #h.model.printAG()
    #h.model.printPath()
    #print("number of attack paths:", len(h.model.allpath))
    
    return h

#=================================================================================================
# Add initial deployment of decoys into network
#=================================================================================================

def add_decoy_vul(node):
    """
    Add vulnerabilities for decoy devices.
    """

    if 'ct' in node.name:
        vul1 = vulNode("CVE-2018-8308")
        vul1.createVul(node, 0.006, 1)
        #https://nvd.nist.gov/vuln/detail/CVE-2018-8136
        #Score: 8.6
        vul2 = vulNode("CVE-2018-8136")
        vul2.createVul(node, 0.012, 1, )
        
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)
    elif 'camera' in node.name:
        #https://nvd.nist.gov/vuln/detail/CVE-2018-6294
        #Score: 10.0
        vul1 = vulNode("CVE-2018-6294")
        vul1.createVul(node, 0.042, 1)  
        vul2 = vulNode("CVE-2018-6295")
        vul2.createVul(node, 0.042, 1) 
        vul3 = vulNode("CVE-2018-6297")
        vul3.createVul(node, 0.042, 1) 
        
        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)
    elif 'tv' in node.name:
        vul1 = vulNode("CVE-2018-4094")
        vul1.createVul(node, 0.012, 1)   
        vul2 = vulNode("CVE-2018-4095")
        vul2.createVul(node, 0.012, 1)  
        
        vul2.thresholdPri(node, 1)
        vul2.terminalPri(node, 1)   
    elif 'server' in node.name:
        #https://nvd.nist.gov/vuln/detail/CVE-2016-1930
        #Score: 10.0
        vul1 = vulNode("CVE-2016-1930")
        vul1.createVul(node, 0.042, 1)    
        vul2 = vulNode("CVE-2016-1935")
        vul2.createVul(node, 0.012, 1) 
        vul3 = vulNode("CVE-2016-1962")
        vul3.createVul(node, 0.042, 1)
        
        vul3.thresholdPri(node, 1)
        vul3.terminalPri(node, 1)
        
    return None

def check_decoy_type(dimension, decoy_num, decoy_list):
    temp = list(accumulate(decoy_num))
    #print(temp, dimension)
    for i in range(0, len(temp)):
        if i == 0:
            if dimension <= temp[i]:
                return decoy_list[i], i+1
        else:
            if dimension > temp[i-1] and dimension <= temp[i]:
                return decoy_list[i], i+1

def add_decoy_type(node, info):
    if "server" in node.name:
        node.type = info["server_decoy_type"]
    else:
        node.type = "emulated"
    return None

def add_decoy_pro(node, info):
    node.pro = info[node.type]

def add_decoy_conn(net):
    temp = []
    for node in net.nodes:
        if "decoy_server" in node.name:
            temp.append(node)
            
    for node in net.nodes:
        if "decoy" in node.name and "server" not in node.name:
            for conNode in temp:
                connectOneWay(node, conNode)
            
    return None

def add_decoy_deployment(net, info):
    
    decoy_net = copyNet(net)
    decoy_num = info["decoy_num"]
    decoy_list = info["decoy_list"]
    temp = []
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):
        name, vlan = check_decoy_type(i+1, decoy_num, decoy_list)
        #print(name, vlan)
        dnode = decoyNode(name+str(i+1))
        dnode.subnet = vlan
        add_decoy_type(dnode, info)
        add_decoy_vul(dnode)
        add_decoy_pro(dnode, info["attackerIntelligence"])
        decoy_net.nodes.append(dnode)
        #A name list of decoys deployed
        #Used in changing connections as binary encodings need to correspond to the decoys
        temp.append(dnode.name) 
    
    #Add connections from decoys to decoys
    add_decoy_conn(decoy_net)
    
    #print("Initial deployment:")
    #printNetWithVul(decoy_net)
    
    return decoy_net, temp

#=================================================================================================
# Add solution into network (change connections)
# If 0 -> 1: add connection
# If 1 -> 0: remove connection
# Others: no change
#=================================================================================================

def add_solution(net, candidate_solution, info, decoy_list):
    """
    Interpret solution to add connections.
    """
    newNet = copyNet(net)
    temp = decoy_list
    #Locate the decoy nodes from the newly created network
    for node1 in newNet.nodes:
        if node1.name in decoy_list:
            temp[decoy_list.index(node1.name)] = node1

    #Add or remove connections from real IoT nodes to decoys
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):    
        num = i * info["riot_num"]
        dnode = temp[i]
        #print(dnode.name)
        for j in range(1, info["riot_num"]+1):
            #print(candidate_solution[num+j-1])
            if candidate_solution[num+j-1] == 1 and info["previous_solution"][num+j-1] == 0:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        connectOneWay(node2, dnode)
            elif candidate_solution[num+j-1] == 0 and info["previous_solution"][num+j-1] == 1:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        disconnectOneWay(node2, dnode)
                        
    #print("Connection changes:")
    #printNetWithVul(newNet)

    return newNet

def add_solution_real_decoy(net, candidate_solution, info, decoy_list):
    """
    Interpret solution to add connections.
    Add or remove connections:
    - from real IoT nodes to decoys
    - from real IoT nodes to real IoT nodes
    """
    newNet = copyNet(net)
    temp = decoy_list
    #Locate the decoy nodes from the newly created network
    for node1 in newNet.nodes:
        if node1.name in decoy_list:
            temp[decoy_list.index(node1.name)] = node1

    #Add or remove connections from real IoT nodes to decoys
    for i in range(0, info["diot_dimension"]+info["dserver_dimension"]):    
        num = i * info["riot_num"]
        dnode = temp[i]
        #print(dnode.name)
        for j in range(1, info["riot_num"]+1):
            #print(candidate_solution[num+j-1])
            if candidate_solution[num+j-1] == 1 and info["previous_solution"][num+j-1] == 0:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        #print("Add connection: ", node2.name, dnode.name)
                        connectOneWay(node2, dnode)
            elif candidate_solution[num+j-1] == 0 and info["previous_solution"][num+j-1] == 1:
                for node2 in newNet.nodes:
                    if node2.id == j:
                        #print("Remove connection: ", node2.name, dnode.name)
                        disconnectOneWay(node2, dnode)
    
    solution1 = (info["diot_dimension"]+info["dserver_dimension"]) * info["riot_num"]
    id_list = range(1, info["riot_num"]+1)
    #Add or remove connections from real IoT nodes to real IoT nodes
    for i in range(0, info["riot_num"]):
        num = i * (info["riot_num"]-1)
        for j in range(0, info["riot_num"]-1): #index of the id_list
            if candidate_solution[solution1+num+j-1] == 1 and info["previous_solution"][solution1+num+j-1] == 0:
                for node3 in newNet.nodes:
                    for node4 in newNet.nodes:
                        temp_list = []
                        for k in id_list:    
                            if k != (i+1):
                                temp_list.append(k) 
                        if node3.id == (i+1) and node4.id == temp_list[j]:
                            #print("Add connection: ", node3.name, node4.name)
                            connectOneWay(node3, node4)
            elif candidate_solution[solution1+num+j-1] == 0 and info["previous_solution"][solution1+num+j-1] == 1:
                for node3 in newNet.nodes:
                    for node4 in newNet.nodes:
                        temp_list = []
                        for k in id_list:    
                            if k != (i+1):
                                temp_list.append(k) 
                        if node3.id == (i+1) and node4.id == temp_list[j]:
                            #print("Remove connection: ", node3.name, node4.name)
                            disconnectOneWay(node3, node4)              
    
    #print("Connection changes:")
    #printNetWithVul(newNet)

    return newNet