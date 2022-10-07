from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import IIntruderPayloadProcessor

import json
import re

extendedTests = False

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.registerIntruderPayloadGeneratorFactory(self)

		callbacks.registerIntruderPayloadProcessor(JsonProcessor())

		return
	
	def getGeneratorName(self):
		return "Logical Fuzzing Engine"

	def createNewInstance(self, attack):
		return LogicalFuzzingEngine(self, attack)

class JsonProcessor(IIntruderPayloadProcessor):
	def getProcessorName(self):
		return "JSON Processor"

	def processPayload(self, currentPayload, originalPayload, baseValue):
		payload = "".join(chr(x) for x in currentPayload)
		return json.dumps(payload)[1:-1]

class LogicalFuzzingEngine(IIntruderPayloadGenerator):
	def __init__(self, extender, attack):
		self._extender = extender
		self._helpers = extender._helpers
		self._attack = attack
		self.maxPayloads = 100
		self.numIterations = 0
		self.payloadList = []
		return

	def hasMorePayloads(self):
		return self.numIterations != self.maxPayloads

	def getNextPayload(self, currentPayload):
		payload = "".join(chr(x) for x in currentPayload)

		if len(self.payloadList) == 0:
			print "Beginning LFE for %s" % payload
			self.payloadList = self.LFE(payload)
			self.maxPayloads = len(self.payloadList)
			print "Max Payloads is now %d" % self.maxPayloads

		payload = self.payloadList.pop(0)

		print "Trying %s" % payload

		self.numIterations += 1

		return str(payload)

	def reset(self):
		self.maxPayloads = 100
		self.numIterations = 0
		self.payloadList = []
		return

	'''
		We want to check type in a specific order. If no type is determined then the value is a string.

		1. Boolean
		2. Integer
		3. Float
		4. String
	'''
	def determineType(self, payload):

		if payload.lower() == "true" or payload.lower() == "false" or payload.lower() == "t" or payload.lower() == "f":
			print "Payload %s is a boolean" % payload
			return bool

		try:
			float(payload)
			if payload.count('.') == 0:
				print "Payload %s is an int" % payload
				return int
			else:
				print "Payload %s is a float" % payload
				return float
		except:
			print "Payload %s is a string" % payload
			return str

	def LFE(self, payload):

		payloadType = self.determineType(payload)

		if payloadType is bool:
			return self.runBool(payload)
		elif payloadType is int:
			return self.runInt(payload)
		elif payloadType is float:
			return self.runFloat(payload)
		elif payloadType is str:
			return self.runString(payload)
		else:
			return payload

	def runBool(self, payload):
		boolList = ["T", "F", "t", "f", "True", "False", "true", "false"]
		return boolList

	def runInt(self, payload):
		print "Beginning int tests"

		intList = [int(payload)]

		# Zero Test
		intList.append(int(0))

		# Negative Test
		intList.append(0 - int(payload))

		# Increment Test
		intList.append(int(payload) + 1)

		# Decrement Test
		intList.append(int(payload) - 1)

		# Double Test
		intList.append(int(payload) * 2)

		# Length Test
		intList.append(int(sys.maxsize))

		# Extended Tests
		if extendedTests:

			# SQL Injection 101
			intList.append(payload + "'")

			# SQL Injection 201
			intList.append(payload + "' or 1=1 -- R")

		print "Returning %s" % intList

		return intList

	def runFloat(self, payload):
		print "Beginning float tests"

		floatList = [float(payload)]

		# Zero Test
		floatList.append(float(0.0))

		# Negative Test
		floatList.append(0 - float(payload))

		# Increment Test
		floatList.append(float(payload) + 1.0)

		# Decrement Test
		floatList.append(float(payload) - 1.0)

		# Double Test
		floatList.append(float(payload) * 2.0)

		# Length Test
		floatList.append(float(sys.float_info.max))

		# Infinity Test
		floatList.append(float("inf"))

		# Extended Tests
		if extendedTests:

			# SQL Injection 101
			floatList.append(payload + "'")

			# SQL Injection 201
			floatList.append(payload + "' or 1=1 -- R")

		print "Returning %s" % floatList

		return floatList

	def runString(self, payload):
		stringList = [payload]

		# One Less Character Test
		stringList.append(payload[0:-1])

		# One More Character Test
		stringList.append(payload + "a")

		# Empty Test
		stringList.append("")

		# Null Test
		stringList.append("null")

		# Length Tests
		for i in range(5, 1000, 100):
			stringList.append(payload + "A" * i)

		# Interpret String
		stringList.extend(self.findData(payload))

		if extendedTests:

			# XSS Test 1
			stringList.append("<script>alert('XSS')</script>")

			# XSS Test 2
			stringList.append("\"><script>alert('XSS')</script>")

			# XSS Test 3
			stringList.append("<svg/onload=alert(1)>")

			# XSS Test 4 (DOM)
			stringList.append("#\"><img src=/ onerror=alert(2)>")

			# XSS Test 5
			stringList.append("<sCrIpT>alert(3)</ScRipt>")

			# XSS Test 6
			stringList.append("<p>")

			# XSS Test 7
			stringList.append("\";alert(0);//")

			# Command Injection 1
			stringList.append(payload + "|whoami")

			# Command Injection 2
			stringList.append(payload + "&whoami")

			# Command Injection 3
			stringList.append(payload + ";whoami")

			# Command Injection 4
			stringList.append(payload + "&&whoami")

			# Command Injection 5
			stringList.append(payload + "||whoami")

			# Command Injection 6
			stringList.append(payload + "$(whoami)")

			# Command Injection 7
			stringList.append(payload + "`whoami`")

		return stringList

	'''
		This method is intended to parse strings for other data types

		Example for the payload: "MYCOUNT:123" this method will extract 123 and include the int payloads in place of it
	'''
	def findData(self, payload):
		newPayloads = []

		intList = re.findall("\\d+", payload)

		for i in intList:
			tmpPayloads = self.runInt(i)
			indices = [m.start() for m in re.finditer(i, payload)]
			newPayloads = self.payloadInterpolate(payload, i, indices, tmpPayloads)

		return newPayloads

	'''
		payloadInterpolate

		This method will loop through all ocurrences of a matched substring within a payload.

		It will interpolate the given payloadList into the payload in place of the original substring.
	'''
	def payloadInterpolate(self, payload, substring, indices, payloadList):
		payloads = []
		for index in indices:
			for payloadValue in payloadList:
				value = payload[0:index] + str(payloadValue) + payload[index + len(substring):]
				payloads.append(value)

		return payloads
