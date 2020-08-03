"""
This module constructs HARMs using AG, AT in both upper and lower layers.
@co-authors: Jin B. Hong, Mengmeng Ge
"""


from attackGraph import *
from attackTree import *

class harm(object):
    """
    Create harm object.
    """
    def __init__(self):
        self.model = None

    def constructHarm(self, net, up, valueUp, lo, valueLow, pri):
        self.model = makeHARM(net, up, valueUp, lo, valueLow, pri)

    
def addToTreeRecursive(gate, childType, val, pri):
    for u in gate.con:
        if u.t is "node":
            if (u.n is not None) and (u.n.vul is not None):
                childType = childType.lower()
                if childType.find("attacktree") >= 0:
                    u.child = at(u.n.vul, val, pri)
                elif childType.find("attackgraph") >= 0:
                    u.child = ag(u.n.vul, val, pri)
                else:
                    print("Error")
        else:
            addToTreeRecursive(u, childType, val, pri)
            
def addToTree(aT, childType, val, pri):
    addToTreeRecursive(aT.topGate, childType, val, pri)
    
def addToGraph(aG, childType, val, pri):
    for u in aG.nodes:
        if (u.n is not None) and (u.n.vul is not None):
            childType = childType.lower()
            if childType.find("attacktree") >= 0:
                u.child = at(u.n.vul, val, pri)
            elif childType.find("attackgraph") >= 0:
                u.child = ag(u.n.vul, val, pri)
            else:
                print("Error")

def makeHARM(net, up, vu, lo, vl, pri):
    """
    Construct HARM.

    :param net: network
    :param up: upper layer type
    :param vu: assign a default value to val parameter for node, no real meaning when initializing, changed and used in security analysis
    :param lo: lower layer type
    :param vl: assign a default value to val parameter for vulnerability, no real meaning when initializing, changed and used in security analysis
    :param pri: assign a privilege value in construction of lower layer vulnerability connections
    :returns: HARM: contains two layers, when using AGAT, \
                    the upper layer is attack graph listing nodes and attack paths \
                    each node has a lower layer which stored in child parameter, containing vulnerability tree
    """
    
    up = up.lower()
    
    #Construct upper layer  
    if up.find("attacktree") >= 0:
        harm = at(net, vu)
    elif up.find("attackgraph") >= 0:
        harm = ag(net, vu)
    else:
        harm = None 
        print("HARM construction error")
    
    #Add lower layer to upper layer
    if harm is not None:
        if type(harm) is ag:
            addToGraph(harm, lo, vl, pri)
            harm.calcPath() #Compute attack path
        else:
            addToTree(harm, lo, vl, pri)

            
    return harm

def removeAT(harm, list):
    """
    Remove attack trees of nodes in a list.
    """
    for node in harm.model.nodes:
        for comproNode in list:
            if node.name == comproNode.name:
                #print(node.name)
                node.child = None
    
    return harm
