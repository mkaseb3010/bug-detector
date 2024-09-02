A bug detection tool created using a python script. This will require you to have a .jar file with some
content to scan for bugs with a given support and confidence threshold levels for the script.

**Required:**
A .jar file in the same path as this script and preferably the latest version of python

**Usage:**
Use a terminal and navigate the path where the .py and .jar (or paste the path of the .jar file location)
file are.
Ensure the support and confidence levels are, Support: 5 and Confidence: 0.75

**For Windows Users:**
Ensure you have python installed properly by running python --version, and then run this command:
python detector.py -jar PATH-TO-YOUR-JAR-FILE.jar -sup 5 -c 0.75

**For MacOS Users:**
If you do not have python installed you can brew install -> brew install python
If you are running the latest version of python then run python3 --version, and then run this command:
python3 detector.py -jar PATH-TO-YOUR-JAR-FILE.jar -sup 5 -c 0.75

**For Linux Users:**
If you do not have python installed you can install using the built in package manager -> sudo apt install python3
Run python3 if your python version is up to date and run
python3 detector.py -jar PATH-TO-YOUR-JAR-FILE.jar -sup 5 -c 0.75

In the event you encounter permission issues to run the script try running the following commands:
chmod +x detector.py 

For missing libraries:
pip or pip3 install missing-library
