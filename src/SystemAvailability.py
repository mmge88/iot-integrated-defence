'''
This module calculates system availability metrics.

Created on 2019.7.24

@author: Mengmeng Ge
'''
from random import uniform

def checkPath(p, harm):
    for node in p:
        if node is not harm.model.s and node is not harm.model.e and node.val > 0:
            if node.type == False:
                return False
    return True

def calcMessageDelivery(harm, dropThresh, modifyThresh):
    """
    Given the network with compromised nodes, calculate the message delivery ratio.
    Assume packet dropping attacks.
    """
    ratio = 0.0
    total = 0
    delivery = 0
    #harm.model.printPath()

    for path in harm.model.allpath:
        if checkPath(path, harm) == True:
            total += 1
            flag = False
            for node in path:
                if node is not harm.model.s and node is not harm.model.e and node.val > 0:
                    #print(node.name)
                    if node.comp == True:
                        pro_drop = uniform(0, 1)
                        if pro_drop < dropThresh:
                            flag = True
                        else:
                            pro_mod = uniform(0, 1)
                            if pro_mod < modifyThresh:
                                flag = True
                                
                                
            if flag == False:
                delivery += 1
    #print("total packets: ", total)
    #print("delivered packets: ", delivery)
    
    return float(delivery)/float(total)
