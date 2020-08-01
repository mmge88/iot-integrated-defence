"""
This module contains node objects.

@author: Mengmeng Ge
"""

from operator import attrgetter
from random import *
from math import *


class node(object):
    """
    Create basic node object.
    """
    
    def __init__(self, name):
        self.name = name
        #Set connections        
        self.con = []
        #Store lower layer info     
        self.child = None
        #Set default value of start/end
        self.isStart = False
        self.isEnd = False
        #self.vul = None
        #self.type = None
        self.subnet = []
        self.inPath = 0
        #Number of attack paths towards decoy server
        self.num = 0
        self.hop = 0
        self.current_hop = 0

    #Set the node as normal/start/end
    def setStart(self):
        self.isStart = True
    def setNormal(self):
        self.isStart = False
        self.isEnd = False
    def setEnd(self):        
        self.isEnd = True
    #Check whether the node is leaf or not
    def isLeaf(self):
        return (len(self.con) is 1)
    
    def calcNodeHopsToTarget(self, hop, maxHop):
        """
        Calculate the maximum number of hops from the node to the target.
        """
        for con in self.con:
            if con.inPath == 0:
                con.inPath = 1
                if con.name.startswith("server") == False:
                    hop = con.calcNodeHopsToTarget(hop, maxHop)
                else:
                    hop += 1
                
                con.inPath = 0
                if hop > maxHop:
                    maxHop = hop
                    
        return hop


class device(node):
    """
    Create smart device object.
    """
    def __init__(self, name):
        super(device, self).__init__(name)
        #Initialize vulnerability network
        self.vul = None
        self.type = None
        self.critical = None
        self.comp = None
        #Initialize subnet which defines device classification
        self.subnet = []
        #For tree topology
        self.height = None
        self.parent = []
        self.comm = []
        self.pro = None
        self.prev_comp = 0.0



class realNode(node):
    #Create a real node in the network
    def __init__(self, name):
        super(realNode, self).__init__(name)
        self.vul = None
        #Indicate real device
        self.type = True
        #Indicate node number
        self.id = None
        #Represent the metric value
        self.val = []
        #Indicate whether node is critical or not
        self.critical = False
        #Represent whether the node is compromised or not
        self.comp = False
        #Indicate the probability of the attacker to proceed using the decoy
        self.pro = 1.0
        #Record previous comprmoise time
        self.prev_comp = 0.0
        

class decoyNode(node):
    #Create a decoy node in the network
    def __init__(self, name):
        super(decoyNode, self).__init__(name)
        self.vul = None
        #Indicate decoy device (emulated or real OS based)
        self.type = False
        #Represent the metric value
        self.val = []
        #Indicate node number
        self.id = -1
        #Indicate whether node is critical or not
        self.critical = None
        #Represent whether the node is compromised or not
        self.comp = False
        #Indicate the probability of the attacker to proceed using the decoy
        self.pro = None
        #Record previous comprmoise time
        self.prev_comp = 0.0




