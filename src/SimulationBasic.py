'''
This module provides "how-to-shuffle" and "when-to-shuffle" schemes used in simulations. 

@author: Mengmeng Ge
'''

from random import Random, uniform, expovariate
from time import time
import inspyred
import logging
import ProblemFormulation as pf
import timeit
import sys
from SDIoTGen import *
from SecurityEvaluator import *
from RandomShufflingOptimization import *
from SystemAvailability import *
from HeuristicAlgo import *


#-----------------------------------------------------------------------------
# Parse solution, save output
#-----------------------------------------------------------------------------

def parse_solution_set(net, solution_set, intelligence, sslThreshold, sslDecrease):
    
    ct_num, camera_num, tv_num, server_num = add_solution_set(solution_set)
    iot_num = getIoTNum(net)
    decoy_iot_num = ct_num + camera_num + tv_num
    
    #threshold is related to first failure condition (system integrity)
    
    info = {"diot_dimension": ct_num + camera_num + tv_num, "dserver_dimension": server_num, 
            "decoy_list": ["decoy_ct", "decoy_camera", "decoy_tv", "decoy_server"], 
            "decoy_num": [ct_num, camera_num, tv_num, server_num], "attackerIntelligence": intelligence,
            "threshold": float(1.0/3.0), "server_decoy_type": "real", "riot_num": iot_num, "sslThreshold": sslThreshold, "weights": [0.5, 0.5],
            "previous_solution": [0] * ((decoy_iot_num + server_num + iot_num - 1) * iot_num), 
            "sslThreshold_checkInterval": sslDecrease, "detectionPro": 0.95}
    return info

def saveOutput(file_name, open_mode, metrics, output_path):
    file = open(output_path+'{}.txt'.format(file_name), open_mode)
    file.writelines(" ".join(metrics))
    file.writelines('\n')
    file.close()
    return None

#-----------------------------------------------------------------------------
# Before shuffling
#-----------------------------------------------------------------------------

def beforeShuffle(node_vlan_list, num, intelligence, sslThreshold, sslDecrease):
    """
    @param num: decoy solution set
    """
    #Create a real network
    
    net = createRealSDIoT(node_vlan_list)
    
    #printNet(net)

    #Add initial decoy deployment
    info = parse_solution_set(net, num, intelligence, sslThreshold, sslDecrease)
    decoy_net, decoy_list = add_decoy_deployment(net, info)
    
    return net, decoy_net, decoy_list, info

def beforeShuffleScale(node_vlan_list, num, intelligence, sslThreshold, sslDecrease, scale):
    """
    @param num: decoy solution set
    """
    #Create a real network
    
    #net = createRealSDIoT(node_vlan_list)
    net = createRealSDIoTScale(node_vlan_list, scale)
    #printNet(net)

    #Add initial decoy deployment
    info = parse_solution_set(net, num, intelligence, sslThreshold, sslDecrease)
    decoy_net, decoy_list = add_decoy_deployment(net, info)
    
    return net, decoy_net, decoy_list, info


#-----------------------------------------------------------------------------
# GA-based shuffling algorithm
#-----------------------------------------------------------------------------

def problemGen(solution_set, node_vlan_list, shuffled_net, previous_solution, intelligence):
    """
    Initialize problem.
    """
    ct_num, camera_num, tv_num, server_num = add_solution_set(solution_set)
    
    decoy_iot_num = ct_num + camera_num + tv_num
    prob_bi = pf.problemBinary(3)

    prob_bi.generate_net(node_vlan_list)
    iot_num = getIoTNum(prob_bi.net) #number of real IoT nodes

    prob_bi.info = {"diot_dimension": decoy_iot_num, "dserver_dimension": server_num, "decoy_list": ["decoy_ct", "decoy_camera", "decoy_tv", "decoy_server"], 
                    "decoy_num": [ct_num, camera_num, tv_num, server_num], "riot_num": iot_num, "attackerIntelligence": intelligence,
                    "threshold": float(1.0/3.0), "server_decoy_type": "real", "parameters": {"size": 100, "generation": 1},
                    "normalized_range": [0.0, 0.0], "previous_solution": previous_solution, "simulation": 100}

    # Assign bits for each dimension
    prob_bi.assign_dimensions_bits_list([1] * ((decoy_iot_num + server_num + iot_num - 1) * iot_num))
    prob_bi.add_real_bounder([1] * ((decoy_iot_num + server_num + iot_num - 1) * iot_num))
    prob_bi.calc_bit_length()
    prob_bi.sim_num = prob_bi.info["simulation"] #For calculation of average expected MTTSF
    #print(prob_bi.dimension_bits, prob_bi.dimensions, prob_bi.dimensions_bits_list, prob_bi.real_bounder)
    
    prob_bi.add_initial_decoy_deployment()
    prob_bi.decoy_net = copyNet(shuffled_net)
    
    return prob_bi

def runCase(node_vlan_list, shuffled_net, previous_solution, solution_set, intelligence):
    
    #Initialize an instance of the random class
    prng = Random()
    #Initialize the random number generator
    #The seed is the current system time
    prng.seed(time())
    
    time_list = {}

    prob_bi = problemGen(solution_set, node_vlan_list, shuffled_net, previous_solution, intelligence)
    
    #start_ea = timeit.default_timer()
    #Initialize an instance of the NSGA2 class (multi-objective) with a random generator 
    ea = inspyred.ec.emo.NSGA2(prng)
    ea.variator = [inspyred.ec.variators.n_point_crossover, 
                   inspyred.ec.variators.bit_flip_mutation]
    
    #Initialize the terminator
    #Return a Boolean value where True implies that the evolution should end
    ea.terminator = [#inspyred.ec.terminators.fitness_limit_termination, 
                     inspyred.ec.terminators.generation_termination]
    
    #Perform the evolution
    #Return a list of individuals contained in the final population  
    
    #start = time()
    
    final_pop = ea.evolve(generator=prob_bi.generator, 
                          evaluator=prob_bi.evaluator, 
                          pop_size=prob_bi.info["parameters"]["size"],
                          maximize=prob_bi.maximize, #A flag to denote maximize (here is True)
                          bounder=prob_bi.bounder, #A basic bounding function (lower bound and upper bound)
                          max_generations=prob_bi.info["parameters"]["generation"],
                          crossover_rate=0.8,
                          mutation_rate=0.2)
    
    """
    final_pop = ea.evolve(generator=prob_bi.generator, 
                          evaluator=inspyred.ec.evaluators.parallel_evaluation_mp,
                          mp_evaluator=prob_bi.evaluator, 
                          mp_num_cpus=2,
                          pop_size=prob_bi.info["parameters"]["size"],
                          maximize=prob_bi.maximize, #A flag to denote maximize (here is True)
                          bounder=prob_bi.bounder, #A basic bounding function (lower bound and upper bound)
                          max_generations=prob_bi.info["parameters"]["generation"],
                          crossover_rate=0.8,
                          mutation_rate=0.2)
    """
    
    #end = time()
    #print("time for computing topology: ", end - start)                                           

    #print("Best archive:", len(ea.archive))
    #print("Final population:", len(final_pop))

    #stop_ea = timeit.default_timer()
    #print(stop_ea - start_ea)
        
    #plot(final_pop, 'full')
    weights = [1.0/3.0, 1.0/3.0, 1.0/3.0]
    
    max_value = 0
    max_solution = None
    
    #Calculate max range
    max_temp = 0.0
    for f in final_pop:
        if f.fitness[0] > max_temp:
            max_temp = f.fitness[0]
            
        if f.fitness[1] > max_temp:
            max_temp = f.fitness[1]
            
    
    
    prob_bi.info["normalized_range"][1] = max_temp
    print("Normalized range: ",  prob_bi.info["normalized_range"])
    
    for f in final_pop:
        #print(f)
        #f.candidate
        
        normalized_list = nomalizeMetrics([f.fitness[0], f.fitness[1], f.fitness[2]], prob_bi.info["normalized_range"])
        value = weights[0] * normalized_list[0] + weights[1] * normalized_list[1] + weights[2] * normalized_list[2]
        if value > max_value:
            max_normalized_list = normalized_list
            max_value = value
            max_solution = f
    print("optimal solution: ", max_solution, "weighted value: ", max_value) 
    return max_solution, prob_bi.info


def runCasePAES(node_vlan_list, shuffled_net, previous_solution, solution_set, intelligence):
    
    #Initialize an instance of the random class
    prng = Random()
    #Initialize the random number generator
    #The seed is the current system time
    prng.seed(time())
    
    time_list = {}

    prob_bi = problemGen(solution_set, node_vlan_list, shuffled_net, previous_solution, intelligence)

    ea = inspyred.ec.emo.PAES(prng)
    ea.variator = [inspyred.ec.variators.n_point_crossover, 
                   inspyred.ec.variators.random_reset_mutation]
    ea.terminator = [inspyred.ec.terminators.evaluation_termination]
    final_pop = ea.evolve(generator=prob_bi.generator, 
                          evaluator=prob_bi.evaluator,
                          pop_size=prob_bi.info["parameters"]["size"],
                          bounder=prob_bi.bounder,
                          maximize=prob_bi.maximize,
                          max_evaluations=200,
                          max_archive_size=100,
                          crossover_rate=0.8,
                          mutation_rate=0.2)
    
    #Perform the evolution
    #Return a list of individuals contained in the final population  
    
    #start = time()

    
    """
    final_pop = ea.evolve(generator=prob_bi.generator, 
                          evaluator=inspyred.ec.evaluators.parallel_evaluation_mp,
                          mp_evaluator=prob_bi.evaluator, 
                          mp_num_cpus=2,
                          pop_size=prob_bi.info["parameters"]["size"],
                          maximize=prob_bi.maximize, #A flag to denote maximize (here is True)
                          bounder=prob_bi.bounder, #A basic bounding function (lower bound and upper bound)
                          max_generations=prob_bi.info["parameters"]["generation"],
                          crossover_rate=0.8,
                          mutation_rate=0.2)
    """
    
    #end = time()
    #print("time for computing topology: ", end - start)                                           

    #print("Best archive:", len(ea.archive))
    #print("Final population:", len(final_pop))

    #stop_ea = timeit.default_timer()
    #print(stop_ea - start_ea)
        
    #plot(final_pop, 'full')
    weights = [1.0/3.0, 1.0/3.0, 1.0/3.0]
    
    max_value = 0
    max_solution = None
    
    #Calculate max range
    max_temp = 0.0
    for f in final_pop:
        if f.fitness[0] > max_temp:
            max_temp = f.fitness[0]
            
        if f.fitness[1] > max_temp:
            max_temp = f.fitness[1]
            
    
    
    prob_bi.info["normalized_range"][1] = max_temp
    print("Normalized range: ",  prob_bi.info["normalized_range"])
    
    for f in final_pop:
        #print(f)
        #f.candidate
        
        normalized_list = nomalizeMetrics([f.fitness[0], f.fitness[1], f.fitness[2]], prob_bi.info["normalized_range"])
        value = weights[0] * normalized_list[0] + weights[1] * normalized_list[1] + weights[2] * normalized_list[2]
        if value > max_value:
            max_normalized_list = normalized_list
            max_value = value
            max_solution = f
    print("optimal solution: ", max_solution, "weighted value: ", max_value) 
    return max_solution, prob_bi.info


#-----------------------------------------------------------------------------
# Fixed interval
#-----------------------------------------------------------------------------

def fixIntervalGA(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, interval, solution_set, intelligence, packet):   
    
    previous_solution = initial_info["previous_solution"]
    i = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    security_failure = False
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    while security_failure == False:
        #Calculate optimal topology
        solution, info = runCasePAES(node_vlan_list, decoy_net, previous_solution, solution_set, intelligence)
        total_cost = float(info["riot_num"] * (info["diot_dimension"] + info["dserver_dimension"] + info["riot_num"] - 1))
        cost = float(total_cost - solution.fitness[2])
        shuffled_net = add_solution_real_decoy(decoy_net, solution.candidate, info, decoy_list)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime, compNodes, comp_decoy_net, security_failure = computeMTTSF_Interval(h, initial_net, shuffled_net, interval, 
                                                                                  initial_info["threshold"], initial_info["detectionPro"], 
                                                                                  compNodes, security_failure)
        
        
        mttsf += totalTime
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        decoy_net = copyNet(comp_decoy_net)
        previous_solution = solution.candidate
        i += 1
    
    #print("Average number of attack paths:", float(sum_ap)/float(i))
    #print("MTTSF:", mttsf)
    #print("Total cost:",  defense_cost)
    #print("Cost per hour:", float(defense_cost/mttsf))
    #print("Average delivery ratio:", float(delivery_ratio/i))

    return str(mttsf), str(float(sum_ap)/float(i)), str(float(defense_cost/mttsf)), str(float(delivery_ratio/i))


def fixIntervalRS(initial_net, decoy_net, initial_info, interval, pro, packet):
    
    i = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    security_failure = False
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    while security_failure == False:
        #print("Shuffle time:",  i+1)
        shuffled_net, cost = randomShuffling(decoy_net, pro)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime, compNodes, comp_decoy_net, security_failure = computeMTTSF_Interval(h, initial_net, shuffled_net, interval, 
                                                                                  initial_info["threshold"], initial_info["detectionPro"], 
                                                                                  compNodes, security_failure)
        
        
        mttsf += totalTime
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        decoy_net = copyNet(comp_decoy_net)
        i += 1
    
    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))

    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i)

def fixIntervalHS(initial_net, decoy_net, initial_info, interval, pro, packet, thre):
    
    i = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    security_failure = False
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]        
    
    totalNodes = len(initial_net.nodes)
    out_degree = float(thre * totalNodes)
    print("Out degree threshold: ", out_degree)
    decoy_net = randomAddReal(decoy_net, pro, out_degree)
    
    while security_failure == False:
        #print("Shuffle time:",  i+1)
        shuffled_net, cost = heuristicShuffling(decoy_net, pro, out_degree)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime, compNodes, comp_decoy_net, security_failure = computeMTTSF_Interval(h, initial_net, shuffled_net, interval, 
                                                                                  initial_info["threshold"], initial_info["detectionPro"], 
                                                                                  compNodes, security_failure)
        
        
        mttsf += totalTime
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        decoy_net = copyNet(comp_decoy_net)
        i += 1
    
    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))

    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i)


#----------------------------------------------------------------------------
#Random interval
#----------------------------------------------------------------------------

def randomIntervalGA(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, mean, solution_set, intelligence, packet):   
    
    previous_solution = initial_info["previous_solution"]
    i = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    security_failure = False
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    while security_failure == False:
        #Calculate optimal topology
        solution, info = runCasePAES(node_vlan_list, decoy_net, previous_solution, solution_set, intelligence)
        total_cost = float(info["riot_num"] * (info["diot_dimension"] + info["dserver_dimension"] + info["riot_num"] - 1))
        cost = float(total_cost - solution.fitness[2])
        shuffled_net = add_solution_real_decoy(decoy_net, solution.candidate, info, decoy_list)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime, compNodes, comp_decoy_net, security_failure = computeMTTSF_RandomInterval(h, initial_net, shuffled_net, mean, 
                                                                                  initial_info["threshold"], initial_info["detectionPro"], 
                                                                                  compNodes, security_failure)
        
        
        mttsf += totalTime
        defense_cost += cost
        sum_ap += totalAP
        #print("Shuffle time:", i+1)
        #print("Number of attack paths:", totalAP)
        #print("MTTSF:", mttsf)
        #print("Cost:", cost)
        #print("Accumulated delivery ratio:", delivery_ratio)
        decoy_net = copyNet(comp_decoy_net)
        previous_solution = solution.candidate
        i += 1
    
    #print("Average number of attack paths:", float(sum_ap)/float(i))
    #print("MTTSF:", mttsf)
    #print("Total cost:",  defense_cost)
    #print("Cost per hour:", float(defense_cost/mttsf))
    #print("Average delivery ratio:", float(delivery_ratio/i))

    return str(mttsf), str(float(sum_ap)/float(i)), str(float(defense_cost/mttsf)), str(float(delivery_ratio/i))


def randomIntervalRS(initial_net, decoy_net, initial_info, mean, pro, packet):
    
    i = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    security_failure = False
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    while security_failure == False:
        #print("Shuffle time:",  i+1)
        shuffled_net, cost = randomShuffling(decoy_net, pro)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime, compNodes, comp_decoy_net, security_failure = computeMTTSF_RandomInterval(h, initial_net, shuffled_net, mean, 
                                                                                  initial_info["threshold"], initial_info["detectionPro"], 
                                                                                  compNodes, security_failure)
        
        
        mttsf += totalTime
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        
        decoy_net = copyNet(comp_decoy_net)
        i += 1
    
    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))
    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i) 

def randomIntervalHS(initial_net, decoy_net, initial_info, mean, pro, packet, thre):
    
    i = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    security_failure = False
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]

    totalNodes = len(initial_net.nodes)
    out_degree = float(thre * totalNodes)
    print("Out degree threshold: ", out_degree)
    decoy_net = randomAddReal(decoy_net, pro, out_degree)
    
    while security_failure == False:
        #print("Shuffle time:",  i+1)
        shuffled_net, cost = heuristicShuffling(decoy_net, pro, out_degree)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime, compNodes, comp_decoy_net, security_failure = computeMTTSF_RandomInterval(h, initial_net, shuffled_net, mean, 
                                                                                  initial_info["threshold"], initial_info["detectionPro"], 
                                                                                  compNodes, security_failure)
        
        
        mttsf += totalTime
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        
        decoy_net = copyNet(comp_decoy_net)
        i += 1
    
    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))
    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i) 


#-----------------------------------------------------------------------------
# Adaptive interval
#-----------------------------------------------------------------------------

def adaptiveIntervalGA(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, solution_set, intelligence, packet):

    previous_solution = initial_info["previous_solution"]
    previous_ssl = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    i = 0
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 (as SSL is set to 1) or SSL threshold is met
    
    while previous_ssl <= initial_info["sslThreshold"]:
        solution, info = runCasePAES(node_vlan_list, decoy_net, previous_solution, solution_set, intelligence)
        total_cost = float(info["riot_num"] * (info["diot_dimension"] + info["dserver_dimension"] + info["riot_num"] - 1))
        cost = float(total_cost - solution.fitness[2])
        shuffled_net = add_solution_real_decoy(decoy_net, solution.candidate, info, decoy_list)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        ssl, mttc, compNodes, comp_decoy_net = computeSSL_Interval(h, initial_net, shuffled_net, 
                                                                  initial_info["sslThreshold_checkInterval"], 
                                                                  initial_info["threshold"], 
                                                                  initial_info["detectionPro"], initial_info["weights"][0], 
                                                                  initial_info["weights"][1], previous_ssl, compNodes)

        mttsf += mttc  
        i += 1          
        defense_cost += cost
        sum_ap += totalAP
        #print("Shuffle time:", i+1)
        #print("Number of attack paths:", totalAP)
        #print("MTTSF:", mttsf)
        #print("Cost:", cost)     
        #print("Accumulated delivery ratio:", delivery_ratio)
               
        previous_solution = solution.candidate
        decoy_net = copyNet(comp_decoy_net)
        previous_ssl = ssl
        
    #print("Average number of attack paths:", float(sum_ap)/float(i))
    #print("MTTSF:", mttsf)
    #print("Total cost:",  defense_cost)
    #print("Cost per hour:", float(defense_cost/mttsf))
    #print("Average delivery ratio:", float(delivery_ratio/i))
    
    return str(mttsf), str(float(sum_ap)/float(i)), str(float(defense_cost/mttsf)), str(float(delivery_ratio/i))

def adaptiveIntervalRS(initial_net, decoy_net, initial_info, pro, packet):

    previous_ssl = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    i = 0
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    while previous_ssl <= initial_info["sslThreshold"]:
        shuffled_net, cost = randomShuffling(decoy_net, pro)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet)     
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        ssl, mttc, compNodes, comp_decoy_net = computeSSL_Interval(h, initial_net, shuffled_net, 
                                                                   initial_info["sslThreshold_checkInterval"], 
                                                                   initial_info["threshold"],
                                                                   initial_info["detectionPro"], initial_info["weights"][0], 
                                                                   initial_info["weights"][1], previous_ssl, compNodes)
        

            
        #print("Shuffled net:")
        #printNetWithVul(decoy_net)
        mttsf += mttc  
        i += 1          
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        
        decoy_net = copyNet(comp_decoy_net)
        previous_ssl = ssl

    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))
    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i)

def adaptiveIntervalHS(initial_net, decoy_net, initial_info, pro, packet, thre):

    previous_ssl = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    i = 0
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    totalNodes = len(initial_net.nodes)
    out_degree = float(thre * totalNodes)
    print("Out degree threshold: ", out_degree)
    decoy_net = randomAddReal(decoy_net, pro, out_degree)
    
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met

    while previous_ssl <= initial_info["sslThreshold"]:
        shuffled_net, cost = heuristicShuffling(decoy_net, pro, out_degree)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet)     
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        ssl, mttc, compNodes, comp_decoy_net = computeSSL_Interval(h, initial_net, shuffled_net, 
                                                                   initial_info["sslThreshold_checkInterval"], 
                                                                   initial_info["threshold"],
                                                                   initial_info["detectionPro"], initial_info["weights"][0], 
                                                                   initial_info["weights"][1], previous_ssl, compNodes)
        

            
        #print("Shuffled net:")
        #printNetWithVul(decoy_net)
        mttsf += mttc  
        i += 1          
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        
        decoy_net = copyNet(comp_decoy_net)
        previous_ssl = ssl

    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))
    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i)

#-----------------------------------------------------------------------------
# Hybrid interval
#-----------------------------------------------------------------------------

def hybridIntervalGA(node_vlan_list, initial_net, decoy_net, decoy_list, initial_info, delay, solution_set, intelligence, packet):

    previous_solution = initial_info["previous_solution"]
    previous_ssl = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    i = 0
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    while previous_ssl <= initial_info["sslThreshold"]:
        solution, info = runCasePAES(node_vlan_list, decoy_net, previous_solution, solution_set, intelligence)
        total_cost = float(info["riot_num"] * (info["diot_dimension"] + info["dserver_dimension"] + info["riot_num"] - 1))
        cost = float(total_cost - solution.fitness[2])
        shuffled_net = add_solution_real_decoy(decoy_net, solution.candidate, info, decoy_list)
        #print("Shuffled net:")
        #printNetWithVul(shuffled_net)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet) 
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        ssl, mttc, compNodes, comp_decoy_net = computeSSL_FixedInterval(h, initial_net, shuffled_net, 
                                                                  initial_info["sslThreshold_checkInterval"], 
                                                                  initial_info["threshold"], 
                                                                  initial_info["detectionPro"], initial_info["weights"][0], 
                                                                  initial_info["weights"][1], previous_ssl, 
                                                                  compNodes, delay)

        mttsf += mttc  
        i += 1          
        defense_cost += cost
        sum_ap += totalAP
        #print("Shuffle time:", i+1)
        #print("Number of attack paths:", totalAP)
        #print("MTTSF:", mttsf)
        #print("Cost:", cost)  
        #print("Accumulated delivery ratio:", delivery_ratio)
                  
        previous_solution = solution.candidate
        decoy_net = copyNet(comp_decoy_net)
        previous_ssl = ssl
        
    #print("Average number of attack paths:", float(sum_ap)/float(i))
    #print("MTTSF:", mttsf)
    #print("Total cost:",  defense_cost)
    #print("Cost per hour:", float(defense_cost/mttsf))
    #print("Average delivery ratio:", float(delivery_ratio/i))
    
    return str(mttsf), str(float(sum_ap)/float(i)), str(float(defense_cost/mttsf)), str(float(delivery_ratio/i))

def hybridIntervalRS(initial_net, decoy_net, initial_info, pro, delay, packet):

    previous_ssl = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    i = 0
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    while previous_ssl <= initial_info["sslThreshold"]:
        shuffled_net, cost = randomShuffling(decoy_net, pro)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        print("Construct HARM")
        h = constructHARM(newnet)     
        totalAP = decoyPath(h)
        print(totalAP)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        ssl, mttc, compNodes, comp_decoy_net = computeSSL_FixedInterval(h, initial_net, shuffled_net, 
                                                                   initial_info["sslThreshold_checkInterval"], 
                                                                   initial_info["threshold"],
                                                                   initial_info["detectionPro"], initial_info["weights"][0], 
                                                                   initial_info["weights"][1], previous_ssl, 
                                                                   compNodes, delay)
        

            
        #print("Shuffled net:")
        #printNetWithVul(decoy_net)
        mttsf += mttc  
        i += 1          
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        
        decoy_net = copyNet(comp_decoy_net)
        previous_ssl = ssl

    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))
    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i)


def hybridIntervalHS(initial_net, decoy_net, initial_info, pro, delay, packet, thre, maxLength):

    previous_ssl = 0
    compNodes = []
    mttsf = 0.0
    defense_cost = 0.0
    sum_ap = 0.0
    i = 0
    
    delivery_ratio = 0.0
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    
    totalNodes = len(initial_net.nodes)
    out_degree = float(thre * totalNodes)
    print("Out degree threshold: ", out_degree)
    decoy_net = randomAddReal(decoy_net, pro, out_degree, maxLength-1)
    #Attacker compromises nodes
    #Shuffle network when SSL check threshold is met 
    #Stop when either SF1 or SF2 or SSL threshold is met
    
    while previous_ssl <= initial_info["sslThreshold"]:
        shuffled_net, cost = heuristicShuffling(decoy_net, pro, out_degree, maxLength-1)
        
        newnet = copyNet(shuffled_net)
        newnet = add_attacker(newnet)
        h = constructHARM(newnet)     
        totalAP = decoyPath(h)
        delivery_ratio += calcMessageDelivery(h, dropThresh, modifyThresh)
        
        ssl, mttc, compNodes, comp_decoy_net = computeSSL_FixedInterval(h, initial_net, shuffled_net, 
                                                                   initial_info["sslThreshold_checkInterval"], 
                                                                   initial_info["threshold"],
                                                                   initial_info["detectionPro"], initial_info["weights"][0], 
                                                                   initial_info["weights"][1], previous_ssl, 
                                                                   compNodes, delay)
        

            
        #print("Shuffled net:")
        #printNetWithVul(decoy_net)
        mttsf += mttc  
        i += 1          
        defense_cost += cost
        sum_ap += totalAP
        print("Shuffle time:", i+1)
        print("Number of attack paths:", totalAP)
        print("MTTSF:", mttsf)
        print("Cost:", cost)
        print("Accumulated delivery ratio:", delivery_ratio)
        
        decoy_net = copyNet(comp_decoy_net)
        previous_ssl = ssl

    print("Average number of attack paths:", float(sum_ap)/float(i))
    print("MTTSF:", mttsf)
    print("Total cost:",  defense_cost)
    print("Cost per hour:", float(defense_cost/mttsf))
    print("Average delivery ratio:", float(delivery_ratio/i))
    
    return mttsf, float(sum_ap)/float(i), float(defense_cost/mttsf), float(delivery_ratio/i)


def baselineScheme(initial_net, initial_info, packet):
    """
    No defence
    """
    i = 0
    compNodes = []
    security_failure = False
    dropThresh = packet["drop"]
    modifyThresh = packet["modify"]
    totalTime = 0.0
    ratio = 0.0
    newnet = copyNet(initial_net)
    
    while security_failure == False:

        attacknet = add_attacker(newnet)
        h = constructHARM(attacknet) 
        
        mttsf, compNodes, attacknet, security_failure = computeMTTSF_Baseline(h, initial_net, attacknet, initial_info["threshold"], initial_info["detectionPro"], compNodes)
        
        tempnet = copyNet(attacknet)
        tempnet = add_attacker(tempnet)
        h = constructHARM(tempnet) 
        delivery_ratio = calcMessageDelivery(h, dropThresh, modifyThresh)
        
        totalTime += mttsf
        ratio += delivery_ratio
        #print("MTTSF:", mttsf)
        #print("Delivery ratio:", delivery_ratio)
        i += 1
        newnet = copyNet(attacknet)
        
    print("MTTSF:", totalTime)
    print("Average delivery ratio:", float(ratio/i))

    return totalTime, float(ratio/i)
