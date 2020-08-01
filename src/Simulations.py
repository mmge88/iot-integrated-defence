'''
This module serves as the entry point for running simulations and setting parameters. 

@author: Mengmeng Ge
'''

from SimulationBasic import *
import time
import multiprocessing
from decimal import *
import RandomShufflingOptimization
from Plots import *

output_path = "path_to_result_folder/"
processor_num = "number_of_processes"

#-------------------------------------------------------------------------------------------------------
# Vary parameter values
#-------------------------------------------------------------------------------------------------------

def varyDecoyNodes():
    num = {"ct":1, "camera":1, "tv":1, "server":1}
    return num

def varyAttackIntelligence():
    intelligence = {'emulated': 0.9, 'real': 1.0}
    return intelligence

def varySSL():
    sslThreshold = 0.1
    return sslThreshold

def varySSLDecrease():
    sslDecrease = 0.01
    return sslDecrease

def varyPacket():
    thresholds = {"drop": 0.5, "modify": 0.5}
    return thresholds

#-------------------------------------------------------------------------------------------------------
# How to shuffle: random shuffling 
#-------------------------------------------------------------------------------------------------------

def randomShuffling(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, pro, sim, packet):
    
    #Fixed interval
    for i in range(0, sim):
            mttsf, ave_ap, cost_hour, ratio = fixIntervalRS(initial_net, decoy_net, initial_info, interval, pro, packet)
            
            if i == 0:
                saveOutput('comparison/fixed_rs', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
            else:
                saveOutput('comparison/fixed_rs', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
            
    
    
    #Random interval
    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = randomIntervalRS(initial_net, decoy_net, initial_info, mean, pro, packet)
        if i == 0:
            saveOutput('comparison/random_rs', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('comparison/random_rs', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
    
    
    #Adaptive interval
    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = adaptiveIntervalRS(initial_net, decoy_net, initial_info, pro, packet)
        if i == 0:
            saveOutput('comparison/adap_rs', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('comparison/adap_rs', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
    
      
    #Hybrid interval
    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = hybridIntervalRS(initial_net, decoy_net, initial_info, pro, delay, packet)
        if i == 0:
            saveOutput('comparison/hybrid_rs', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('comparison/hybrid_rs', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
    
    return None


#-------------------------------------------------------------------------------------------------------------
# How to shuffle: GA
#-------------------------------------------------------------------------------------------------------------

def fixedInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, pro, sim, packet):


    pool = multiprocessing.Pool(processes=processor_num)
    objects = [pool.apply_async(fixIntervalGA, args=(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, 
                                                     varyDecoyNodes(), varyAttackIntelligence(), packet)) for i in range(0, sim)]
    pool.close()
    pool.join()
    
    #results = [r.get() for r in objects]
    #print(results)
    for r in objects:
        saveOutput('comparison/fixed_ga', 'a+', r.get(), output_path)
    
    return None
  
def randomInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, mean, pro, sim, packet):
    
    pool = multiprocessing.Pool(processes=processor_num)
    objects = [pool.apply_async(randomIntervalGA, args=(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, mean, 
                                                        varyDecoyNodes(), varyAttackIntelligence(), packet)) for i in range(0, sim)]
    pool.close()
    pool.join()
    
    #results = [r.get() for r in objects]
    #print(results)
    for r in objects:
        saveOutput('comparison/random_ga', 'a+', r.get(), output_path)
    
    return None

def adaptiveInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, pro, sim, packet):
    
    pool = multiprocessing.Pool(processes=processor_num)
    objects = [pool.apply_async(adaptiveIntervalGA, args=(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, 
                                                          varyDecoyNodes(), varyAttackIntelligence(), packet)) for i in range(0, sim)]

    pool.close()
    pool.join()
    
    #results = [r.get() for r in objects]
    #print(results)
    for r in objects:
        saveOutput('comparison/adap_ga', 'a+', r.get(), output_path)
    
    return None

def hybridInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, pro, delay, sim, packet):
    
    pool = multiprocessing.Pool(processes=processor_num)
    objects = [pool.apply_async(hybridIntervalGA, args=(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, delay, 
                                                        varyDecoyNodes(), varyAttackIntelligence(), packet)) for i in range(0, sim)]
   
    pool.close()
    pool.join()
    
    #results = [r.get() for r in objects]
    #print(results)
    for r in objects:
        saveOutput('comparison/adap_ga', 'a+', r.get(), output_path)
    
    return None

#------------------------------------------------------------------------------------------------------
# How to shuffle: heuristic algorithm (DPNT)
#------------------------------------------------------------------------------------------------------

def heuShuffling(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, pro, sim, packet, delay, thre):
    
    #Fixed interval
    for i in range(0, sim):
            mttsf, ave_ap, cost_hour, ratio = fixIntervalHS(initial_net, decoy_net, initial_info, interval, pro, packet, thre)
            if i == 0:
                saveOutput('comparison/fixed_heu', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
            else:
                saveOutput('comparison/fixed_heu', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)


    #Random interval
    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = randomIntervalHS(initial_net, decoy_net, initial_info, mean, pro, packet, thre)
        if i == 0:
            saveOutput('comparison/random_heu', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('comparison/random_heu', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
  
    #Adaptive interval
    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = adaptiveIntervalHS(initial_net, decoy_net, initial_info, pro, packet, thre)
        if i == 0:
            saveOutput('comparison/adap_heu', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('comparison/adap_heu', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
    
    #Hybrid interval
    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = hybridIntervalHS(initial_net, decoy_net, initial_info, pro, delay, packet, thre)
        
        if i == 0:
            saveOutput('comparison/hybrid_heu', 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('comparison/hybrid_heu', 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)

    return None

#------------------------------------------------------------------------------------------------------
# Impact analysis on network size
#------------------------------------------------------------------------------------------------------

def scalabilityAnalysis(node_vlan_list, interval, pro, sim, delay, out_degree_ratio, scale):
    decoy_num = {"ct":2, "camera":2, "tv":2, "server":1}
    
    initial_net, decoy_net, decoy_list, initial_info = beforeShuffleScale(node_vlan_list, decoy_num, varyAttackIntelligence(), 
                                                                          varySSL(), varySSLDecrease(), scale)



    for i in range(0, sim):
        mttsf, ave_ap, cost_hour, ratio = hybridIntervalHS(initial_net, decoy_net, initial_info, pro, delay, varyPacket(), out_degree_ratio)
        if i == 0:
            saveOutput('scalability/hybrid_heu'+str(scale), 'w', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
        else:
            saveOutput('scalability/hybrid_heu'+str(scale), 'a+', [str(mttsf), str(ave_ap), str(cost_hour), str(ratio)], output_path)
    
    
    return None

#------------------------------------------------------------------------------------------------------
# No defence
#------------------------------------------------------------------------------------------------------

def noDefence(initial_net, initial_info, sim):

    for i in range(0, sim):
        mttsf, ratio = baselineScheme(initial_net, initial_info, varyPacket())
        if i == 0:
            saveOutput('no-defence/baseline', 'w', [str(mttsf), str(ratio)])
        else:
            saveOutput('no-defence/baseline', 'a+', [str(mttsf), str(ratio)])


if __name__ == '__main__':
    
    """
    Run simulations with baseline scenario
    - Random shuffling
    - DPNT
    - GA
    - No defence
    """
    node_vlan_list = [['mri', 'ct'], ['thermostat', 'meter', 'camera'], ['tv', 'laptop'], ['server']]
    
    initial_net, decoy_net, decoy_list, initial_info = beforeShuffle(node_vlan_list, varyDecoyNodes(), varyAttackIntelligence(), 
                                                                     varySSL(), varySSLDecrease())
    
    interval = 24.0 #For fixed interval
    mean = 24.0 #For random interval
    pro = 0.5 #For random shuffling algorithm
    sim = 100
    delay = 120.0 #For fixed interval in hybrid shuffling
    out_degree_ratio = 1.0
    scale = 2 #Set the number for real IoT devices (thermostat, meter, camera, tv, laptop)
    
    start = time.time()

    #randomShuffling(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, pro, sim, varyPacket())
    
    heuShuffling(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, pro, sim, varyPacket(), delay, out_degree_ratio)
    
    # GA shuffling using multiprocessing
    #fixedInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, pro, sim, varyPacket())
    #randomInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, mean, pro, sim, varyPacket())
    #adaptiveInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, pro, sim, varyPacket())
    #hybridInterval(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, pro, delay, sim, varyPacket())
    
    
    #noDefence(initial_net, initial_info, sim)
    end = time.time()
    print("time: ", end - start)
    
    
    """
    Scalability analysis
    """
    #scalabilityAnalysis(node_vlan_list, interval, pro, sim, delay, out_degree_ratio, scale)
    
    """
    Plot results
    """
    
    processResult(100, output_path)


