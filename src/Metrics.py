"""
This module contains functions for calculating path-based metrics.

@author: Mengmeng Ge
"""  

import math

#------------------------------------
#Compute the number of paths
#------------------------------------
def NP_metric(harm):
    
    value = len(harm.model.allpath)
    return value

#------------------------------------------
#Compute the mean of path lengths
#------------------------------------------
def MPL_metric(harm):

    sum_path_length = 0
    for path in harm.model.allpath:
        sum_path_length += int(len(path)-3)
        #print(sum_path_length)

    value = float(sum_path_length/len(harm.model.allpath))

    return value

#----------------------------------------
#Compute the mode of path lengths
#----------------------------------------
def MoPL_metric(harm):
    
    NP = []
    for path in harm.model.allpath:
        NP.append(int(len(path)-3))

    value = max(NP, key=NP.count)
    return value

#----------------------------------------------------------
#Compute the standard deviation of path lengths
#----------------------------------------------------------
def SDPL_metric(harm):

    sumation_DPL = 0
    MPL = MPL_metric(harm)
    #print(MPL)
    for path in harm.model.allpath:    
        sumation_DPL += float(len(path) - 3 - MPL)**2
        #print(sumation_DPL)

    value = math.sqrt(float(sumation_DPL / len(harm.model.allpath)))

    return value

#--------------------------------------
#Compute the shortest attack path
#--------------------------------------
def SP_metric(harm):

    SP=[]
    for path in harm.model.allpath:
        SP.append(int(len(path)-3))
    value = min(SP)
    return value

#===================================================================================
#Compute the number of real attack paths and decoy attack paths
#===================================================================================
def decoyPath(h):
    """
    @return: number of decoy attack paths
    @return: number of real attack paths
    """
    dsum = 0
    rsum = 0
    for path in h.model.allpath:
        if 'decoy_server' in path[len(path)-2].name:
            dsum += 1
        elif 'server' in path[len(path)-2].name:
            rsum += 1
    #print(dsum, float(dsum)/float(dsum+rsum))
    return dsum

def decoyPathPct(harm):
    """
    @return: the percentage of attack paths with decoy nodes as entry points among all decoy attack paths (to decoy server)
    """
    dsum = 0.0
    rsum = 0.0
    for path in harm.model.allpath:
        if 'svrd' in path[len(path)-2].name:
            dsum+=1.0
        elif 'svr' in path[len(path)-2].name:
            rsum+=1.0
    return float(dsum)/float(dsum+rsum)
            

def decoyNodePct(harm):
    dsum = 0.0
    pct = 0.0
    for path in harm.model.allpath:
        if 'svrd' in path[len(path)-2].name:
            dsum+=1.0
            decoysum = 0.0
            for n in path:
                if n.name != 'ag_attacker' and n != harm.model.e and n != harm.model.s and n.type == False:
                    decoysum+=1.0
            pct+=float(decoysum/(len(path)-3.0))
            #print("pct", pct)
    if dsum == 0.0:
        return 0.0
    return float(pct/dsum)
        
def decoyProceedPro(harm):
    dsum = 0.0
    pro = 0.0
    for path in harm.model.allpath:
        if 'svrd' in path[len(path)-2].name:
            dsum+=1.0
            pro_path = 1.0
            for n in path:
                if n.name != 'ag_attacker' and n != harm.model.e and n != harm.model.s:
                    #print(n.name)
                    pro_path*=float(n.pro)
            pro += pro_path
            #print("pro", pro)
        
    if dsum == 0.0:
        return 1.0
    return float(pro/dsum)

#====================================================================================
#Compute the cost of solutions
#====================================================================================
def solutionCost(candidate_solution, info):
    """
    Calculate the total cost of deployed solutions: connections
    """
    total_cost = info["riot_num"] * (info["diot_dimension"] + info["dserver_dimension"] + info["riot_num"] - 1)
    solution_cost = 0.0
    for i in range(0, total_cost):
        if candidate_solution[i] != info["previous_solution"][i]: 
            solution_cost += 1.0
    
    return float(total_cost - solution_cost)

#====================================================================================
#Normalize metric values
#====================================================================================
def nomalizeMetrics(metric_list, normalized_range):
    normalized_value_list = []
    min_value = normalized_range[0]
    max_value = normalized_range[1]
    #print("Before normalization", metric_list)
    for i in metric_list:
        temp = float(i - min_value)/float(max_value - min_value)
        normalized_value_list.append(temp)
    return normalized_value_list
    