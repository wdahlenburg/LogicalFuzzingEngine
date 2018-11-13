# Logical Fuzzing Engine
A Burpsuite extension written in Python to perform basic validation fuzzing.

This plugin creates an Intruder payload generator to fuzz based on the payloads type.

The engine will attempt to run a series of test for each type. It includes an interpolation technique to modify strings with numbers within them.

Extended Tests can be run to test for SQL Injection, XSS, and Command Injection. 

This plugin works best when a Live Task is setup to audit Intruder requests.

### Requirements
[Jython](http://www.jython.org/downloads.html)

### How to use
1. Add the extension into extender
2. Send a request to Intruder
3. Apply the attack type of your choice
4. Switch to the payloads tab
5. Choose Extension-generated for the payload number you want to fuzz
6. Click Select Generator
7. Select Logical Fuzzing Engine
8. Click Start Attack
