'''
This module provides the multi-objective GA for computing optimal network topology used in MTD.

@author: Mengmeng Ge
'''

import warnings
import copy
from inspyred import ec
from inspyred.ec import emo
from inspyred.ec import selectors
import itertools
import math
from SDIoTGen import *
from SecurityEvaluator import *
import time

class problem(object):
    def __init__(self, objectives=1):
        """
        dimensions: the number of inputs to the problem, currently not used
        dimensions_bits_list: list of number of bits for each input dimension
        objectives: the number of outputs of the problem (default 1)
        bounder: the bounding function for the problem (default None)
        maximize: whether the problem is one of maximization (default True)
        """
        #self.dimensions = dimensions
        self.objectives = objectives
        self.bounder = None
        self.maximize = True
        self.dimensions_bits_list = None
        self.dimension_bits = 0
        self.net = None
        self.decoy_net = None #Store net with initial decoy deployment and then shuffled net afterwards
        self.info = None
        self.real_bounder = None
        self.decoy_list = None
        self.sim_num = None
        
    def generator(self, random, args):
        """The generator function for the problem."""
        raise NotImplementedError
        
    def evaluator(self, candidates, args):
        """The evaluator function for the problem."""
        raise NotImplementedError
        
    def __call__(self, *args, **kwargs):
        # allows that function to accept an arbitrary number of arguments and keyword arguments
        candidate = [a for a in args]
        fit = self.evaluator([candidate], kwargs)
        return fit[0]

    
class problemBinary(problem):
    def __init___(self):
        problem.__init__(self, 2)
        self.bounder = ec.DiscreteBounder([0, 1])
        self.maximze = True

    def assign_dimensions_bits_list(self, dimensions_bits_list):
        """
        A list of length of dimension bits.
        Each input/dimension may have different length of bits.
        """
        self.dimensions_bits_list = dimensions_bits_list
    
    def generate_net(self, node_vlan_list):
        self.net = createRealSDIoT(node_vlan_list)

    def add_initial_decoy_deployment(self):
        self.decoy_net, self.decoy_list = add_decoy_deployment(self.net, self.info)
        
    def calc_bit_length(self):
        """
        Calculate the total number of bits encoded for the solution.
        """
        for i in range(0, len(self.dimensions_bits_list)):
            self.dimension_bits += self.dimensions_bits_list[i]
        #print("bits", self.dimension_bits)
    
    def add_real_bounder(self, bounder_list):
        """
        Assign the bounder in real numbers for the solution.
        """
        self.real_bounder = bounder_list
    
    def generator(self, random, args):
        candidate = [random.choice([0, 1]) for _ in range(0, self.dimension_bits)]
        return candidate
        
    def evaluator(self, candidates, args):
        
        fitness = []
        for c_binary in candidates:
            #print("binary solution:", c_binary)
            #net = add_solution(self.decoy_net, c_binary, self.info, self.decoy_list)
            net = add_solution_real_decoy(self.decoy_net, c_binary, self.info, self.decoy_list)
            newnet = add_attacker(net)
            #print("Add attacker:")
            #printNet(newnet)
            harm = constructHARM(newnet)

            f1 = decoyPath(harm) 
            f2 = float(sum([computeMTTSF(harm, self.net, self.info["threshold"]) for i in range(0, self.sim_num)])/self.sim_num)
            f3 = solutionCost(c_binary, self.info)
            
            #print(f1, f2, f3)
            fitness.append(emo.Pareto([f1, f2, f3])) # a Pareto multi-objective solution
     
        return fitness