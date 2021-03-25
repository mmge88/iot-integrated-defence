# Integrated Defence for IoT

The project proposes an integrated defence optimisation approach for IoT using network shuffling-based MTD and cyber deception.

The entry point of the project is Simulations.py. Simulations use an example network (fig-iot-example.png) and compare 12 schemes (when to shuffle and how to shuffle) and scheme with no defence. All parameters are set manually. Please change the global variables in Simulations.py (output_path and processor_num) and create folders with the matching name specified in methods to store results before running the simulations. 

Increasing IoT nodes and decoy nodes is supported by scalabilityAnalysis method in Simulations.py. Two variables (out_degree_ratio to specify the maximum number of outgoing connections to other real nodes; maxLength to specify the maximum path length) are used to control the computational complexity of paths.

### Requirements
* At least Python 3.6+
* Inspyred (https://github.com/aarongarrett/inspyred) for GA
* Matplotlib for visualising results
