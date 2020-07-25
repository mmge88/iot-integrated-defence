'''
This module produces plots to visualise the results. 

@author: Mengmeng Ge
'''

import matplotlib.pyplot as plt
import itertools
from matplotlib import cm, hatch
from matplotlib import collections  as mc
import pylab as pl
import math
import re
import numpy as np
import matplotlib.ticker as plticker
from jsonschema._validators import pattern


scheme = ['fixed', 'random', 'adap', 'hybrid']
patterns = [ "/" , "\\" , "|" , "-" , "+" , "x", "o", "O", ".", "*" ]
colors = ['#4B8BBE', '#DC143C', '#646464']


def reformat_large_tick_values(tick_val, pos):
    """
    Turns large tick values (in the billions, millions and thousands) 
    Such as 4500 into 4.5K and also appropriately turns 4000 into 4K (no zero after the decimal)
    """
    if tick_val >= 1000000000:
        val = round(tick_val/1000000000, 1)
        new_tick_format = '{:}B'.format(val)
    elif tick_val >= 1000000:
        val = round(tick_val/1000000, 1)
        new_tick_format = '{:}M'.format(val)
    elif tick_val >= 1000:
        val = round(tick_val/1000, 1)
        new_tick_format = '{:}K'.format(val)
    elif tick_val < 1000:
        new_tick_format = round(tick_val, 1)
    else:
        new_tick_format = tick_val

    # make new_tick_format into a string value
    new_tick_format = str(new_tick_format)
    
    # code below will keep 4.5M as is but change values such as 4.0M to 4M since that zero after the decimal isn't needed
    index_of_decimal = new_tick_format.find(".")
    
    if index_of_decimal != -1:
        value_after_decimal = new_tick_format[index_of_decimal+1]
        if value_after_decimal == "0":
            # remove the 0 after the decimal point since it's not needed
            new_tick_format = new_tick_format[0:index_of_decimal] + new_tick_format[index_of_decimal+2:]
            
    return new_tick_format

def plotSchemes(bars1, bars2, bars3, interval, ylabel):
    # set width of bar
    barWidth = 0.15
    _, ax = plt.subplots()
    # Set position of bar on X axis
    r1 = np.arange(len(bars1))
    r2 = [x + barWidth for x in r1]
    r3 = [x + barWidth for x in r2]
     
    # Make the plot
    plt.bar(r1, bars1, color=colors[0], width=barWidth, hatch='/', label='RNT')
    plt.bar(r2, bars2, color=colors[1], width=barWidth, hatch='-', label='GANT')
    plt.bar(r3, bars3, color=colors[2], width=barWidth, hatch='\\', label='DPNT')
    
    ax.set_xlabel('Shuffling strategy', fontsize=50)
    ax.set_ylabel(ylabel, fontsize=50)
    #ax.xaxis.set_ticks(['RNT', 'GANT', 'DPNT'])
    ax.tick_params(axis='both', which='major', labelsize=50)
    #ax.margins(0.1)

    plt.xticks([r + barWidth for r in range(len(bars1))], ['FS', 'RS', 'AS', 'HS'], fontsize=50)
    loc = plticker.MultipleLocator(base=interval) # this locator puts ticks at regular intervals
    ax.yaxis.set_major_locator(loc)
    ax.yaxis.set_major_formatter(plticker.FuncFormatter(reformat_large_tick_values))
    # Create legend & Show graphic
    plt.legend(fontsize=50)
    pl.grid()
    plt.show()
    return None

def calc_ave(values):
    v = 0
    for i in values:
        v += i
    return v

def processResult(sim, input_path):

    rnt_ap = []
    rnt_mttsf = []
    rnt_cost = []
    rnt_del = []
    gant_ap = []
    gant_mttsf = []
    gant_cost = []
    gant_del = []
    dpnt_ap = []
    dpnt_mttsf = []
    dpnt_cost = []
    dpnt_del = []

    for name in scheme:
        print("random shuffling " + name)
        
        with open(input_path+'comparison/{}_{}.txt'.format(name, 'rs'), 'r') as file:
            ap = 0.0
            mttsf = 0.0
            cost = 0.0
            delivery = 0.0
            i = 0
            for line in file:
                i += 1
                items = line.split(' ')
                #print(items)
                mttsf += float(items[0])
                ap += float(items[1])
                cost += float(items[2])
                delivery += float(items[3].strip('\n'))
            
            print("Simulations: ", i)
            ave_mttsf = float(mttsf / sim)
            ave_ap = float(ap / sim)
            ave_cost = float(cost / sim)
            ave_delivery = float(delivery / sim)
            print(ave_mttsf, ave_ap, ave_cost, ave_delivery)
        
        rnt_ap.append(ave_ap)
        rnt_mttsf.append(ave_mttsf)
        rnt_cost.append(ave_cost)
        rnt_del.append(ave_delivery)

    
    
    for name in scheme:
        print("Heuristic shuffling " + name)
        
        with open(input_path+'comparison/{}_{}.txt'.format(name, 'heu'), 'r') as file:
            ap = 0.0
            mttsf = 0.0
            cost = 0.0
            delivery = 0.0
            i = 0
            for line in file:
                i += 1
                items = line.split(' ')
                #print(items)
                mttsf += float(items[0])
                ap += float(items[1])
                cost += float(items[2])
                delivery += float(items[3].strip('\n'))
                
            print("Simulations: ", i)
            ave_mttsf = float(mttsf / sim)
            ave_ap = float(ap / sim)
            ave_cost = float(cost / sim)
            ave_delivery = float(delivery / sim)
            print(ave_mttsf, ave_ap, ave_cost, ave_delivery)
        

        dpnt_ap.append(ave_ap)
        dpnt_mttsf.append(ave_mttsf)
        dpnt_cost.append(ave_cost)
        dpnt_del.append(ave_delivery)

    for name in scheme:
        print("GA shuffling " + name)
        
        with open(input_path+'comparison/{}_{}.txt'.format(name, 'ga'), 'r') as file:
            ap = 0.0
            mttsf = 0.0
            cost = 0.0
            delivery = 0.0
            i = 0
            for line in file:
                i += 1
                items = line.split(' ')
                #print(items)
                mttsf += float(items[0])
                ap += float(items[1])
                cost += float(items[2])
                delivery += float(items[3].strip('\n'))
                
            print("Simulations: ", i)
            ave_mttsf = float(mttsf / sim)
            ave_ap = float(ap / sim)
            ave_cost = float(cost / sim)
            ave_delivery = float(delivery / sim)
            print(ave_mttsf, ave_ap, ave_cost, ave_delivery)
        

        gant_ap.append(ave_ap)
        gant_mttsf.append(ave_mttsf)
        gant_cost.append(ave_cost)
        gant_del.append(ave_delivery)

    plotSchemes(rnt_ap, gant_ap, dpnt_ap, 2000.0, 'Average number of attack paths \n towards decoy target')
    plotSchemes(rnt_mttsf, gant_mttsf, dpnt_mttsf, 50.0, 'Average MTTSF')
    plotSchemes(rnt_cost, gant_cost, dpnt_cost, 0.2, 'Average cost per hour')
    plotSchemes(rnt_del, gant_del, dpnt_del, 0.2, 'Average packet delivery ratio')
    
    print(float(calc_ave(gant_ap))/4.0)
    print(float(calc_ave(rnt_ap))/4.0)
    print(float(calc_ave(dpnt_ap))/4.0)
    print(float(calc_ave(dpnt_cost))/4.0)
    
    return None

    