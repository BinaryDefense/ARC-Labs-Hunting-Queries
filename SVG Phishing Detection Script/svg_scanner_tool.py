import sys
import os
import math
from collections import Counter
import re

filenames = sys.argv[1:]

if len(sys.argv) < 2:
    filenames_input = input("Enter one or more filenames or 'all' in order to scan all files in the local folder. You can also enter 'help' for more instructions:")
    filenames = filenames_input.split(" ")

if filenames[0].lower() == "help":
    print("This tool is designed to scan .svg files for indicators of malicious content.")
    print("Files to scan are passed in as command line arguments, or as user input if the script is run with no arguments.")
    print("Special Arguments:")
    print("'all': scans every file in the local directory.")
    print("'help': prints this help page.")
    print("the following tests are done:")
    print("Entropy is reported. Entropy higher than ___ should be considered suspicious. False positives are possible if a legitimate SVG includes a base64 encoded JPG or PNG.")
    print("Script tags are checked for. Script tags are used to embed active content including javascript. False positives are possible if a legitimate SVG is intended to be interactive, but the vast majority are not - most results are suspicious. High entropy + script tags is highly suspicious.")
    print("embedded images with an xlink:href link directing to a malicious script. This is a sneaky way to redirect to malicious code without high entropy or using script tags.")


if filenames[0].lower() == "all":
    print("Handling all svg files in local directory")
    filenames = []
    for (root, dirs, files) in os.walk(os.getcwd()):
        for file in files:
            if '.svg' in file:
                #print(root + "\\" + file)
                filenames.append(root + "\\" + file)
else:
    for index, filename in enumerate(filenames):
        print(filename)
        if (filename[0] == "."):
            #print("replacement:")
            filenames[index] = os.getcwd() + "\\" + filename[2:]
            #print(filenames[index])
        elif ("\\" not in filename):
            #print("replacement:")
            filenames[index] = os.getcwd() + "\\" + filename
            #print(filenames[index])
        
#print(filenames)

for filename in filenames:
    print("\n\n")
    print("inspecting " + filename)

    file_handle = open(filename, 'r', encoding='utf-8')
    file_contents = file_handle.read()
    #print(file_contents)

    # test 1 = check entropy
    print("Test 1: Checking file entropy:")

    file_bytes = file_contents.encode("utf-8")

    entropy = 0.0
    for count in Counter(file_bytes).values():
        probability = count / len(file_bytes)
        if probability > 0:  # Avoid log(0)
            entropy -= probability * math.log2(probability)


    if (entropy < 5.5):
        print("passed - low entropy: " + str(entropy))
    elif (entropy >= 5.5 and entropy < 6.0):
        print("SUSPICIOUS - medium entropy: " + str(entropy))
    elif (entropy >= 6.0):
        print("VERY SUSPICIOUS - high entropy: " + str(entropy))
    


    # test 2 = check for script tags
    print("Test 2: Checking for script tags:")

    if ("<script" in file_contents) or ("</script>" in file_contents):
        print("VERY SUSPICIOUS - Script tags found!!")
    else:
        print("passed - no script tags")


    # test 3 = check for xlink:href to script (check by file extension)
    print("Test 3: Checking for href to script:")

    pattern  = 'xlink:href=".*\\.(bat|js|sh|py|vbs|ps1).*">'

    match = re.search(pattern, file_contents)

    if match:
            redirect_link = match.group()
            
            #print(redirect_link)

            redirect_link_domain = redirect_link.replace('xlink:href="https://', '').split('/')[0]
            redirect_link_file = redirect_link.replace('xlink:href="https://', '').split('/')[-1].split('?')[0]
            

            print(f"VERY SUSPICIOUS - script redirect link found: Domain: {redirect_link_domain}, Filename: {redirect_link_file}")  # Output: Match found: word:cat
    else:
        print("passed - no suspicious redirect links")