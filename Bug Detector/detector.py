import argparse
import os
from collections import defaultdict

JAR_File = ""
support_threshold = 0
confidence_threshold = 0.0
call_pairs = {}

#Adjust out arguments to be parsed accordingg to out allowed parameters
def parse_arguments():
    global JAR_File, support_threshold, confidence_threshold
    parser = argparse.ArgumentParser(description = "Rule-Based Bug Detector")
    parser.add_argument("-jar", type = str, required = True, help = "Path to the JAR file")
    parser.add_argument("-sup", type = int, default = 5,  help = "Support threshold (default: 5)")
    parser.add_argument("-c", type = float, default = 0.75, help = "Confidence threshold (default: 0.75)")
    args = parser.parse_args()
    JAR_File = args.jar
    support_threshold = args.sup
    confidence_threshold = args.c
    return parser.parse_args()

#This gets the call graph that is generated, since there was an error in the pathing
#I decided to use an output.txt that gets generated with all the call graph details inside
def get_call_graph(call_pairs, method_pairs):
    with open("output.txt", 'r', encoding = 'utf-8') as output:
        for line in output:
            caller_hash, callee_hash = line.split()
            if caller_hash not in call_pairs:
                call_pairs[caller_hash] = {}
            if callee_hash not in call_pairs:
                call_pairs[caller_hash][callee_hash] = 0
                if callee_hash in method_pairs:
                    method_pairs[callee_hash] += 1
                else:
                    method_pairs[callee_hash] = 1

#This loads the call graph
def call_graphs(file): 
    call_graph = defaultdict(dict)
    method_pairs = {}
    get_call_graph(call_graph, method_pairs)
    return call_graph, method_pairs

#Gets the frequent pairs that are all over our output file
def get_frequency_pairs(call_pairs, method_pairs):
    frequency_pair = {}
    for caller, callees in call_pairs.items():
        callees_len = list(callees)
        for i in range(len(callees_len)):
            for j in range(i + 1, len(callees_len)):
                part1 = (callees_len[i], callees_len[j])
                part2 = (callees_len[j], callees_len[i])
                frequency_pair[part1] = frequency_pair.get(part1, 0) + 1
                frequency_pair[part2] = frequency_pair.get(part2, 0) + 1
    return frequency_pair

#Should enure only unique pairs are going to be displayed and unique bugs to be shown
def get_method_pairs(frequency_pair, method_pairs):
    method_pair = {}
    for pair, pair_s in frequency_pair.items():
        if pair[1] in method_pairs:
            c = pair_s / method_pairs[pair[0]]
            if c >= confidence_threshold:
                method_pair[pair] = c
    return method_pair

#Detects all the bugs in our gien file
def detect_bugs(confidence_pairs, call_pairs, frequency_pairs):
    bugs = []
    for pair, confidence in confidence_pairs.items():
        for caller, callees in call_pairs.items():
            if pair[0] in callees and pair[1] not in callees:
                bugs.append((pair[0], caller, pair, frequency_pairs[pair], confidence))
    return bugs  

#Prints the bugs in the required format
def print_bugs(bugs): 
    if not bugs:
        print("No bugs found!")
    else:
        for bug in bugs:
            function, pairs, pair, support, confidence = bug
            print(f"Bug: {function} in {pairs}, pair: ({pair[0]}, {pair[1]}), Support: {support}, Confidence: {confidence * 100:.2f}%") 

#Executes the output file automatically when we run our command line for the script
def command_exec():
    args = parse_arguments()
    command = f"java -jar javacg-0.1-SNAPSHOT-static.jar {args.jar} > output.txt"
    os.system(command)

#Call all of the above function with their respected parameters
def main():
    command_exec()
    call_pairs, method_pairs = call_graphs("output.txt")
    frequency_pair = get_frequency_pairs(call_pairs, method_pairs)
    method_pair = get_method_pairs(frequency_pair, method_pairs)
    bugs = detect_bugs(method_pair, call_pairs, frequency_pair)
    print_bugs(bugs)

if __name__ == "__main__":
    main()
