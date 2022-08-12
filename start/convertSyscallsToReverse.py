import os
import json
class EMU():
    def __init__(self):
        self.maxCounter = 500000
        self.arch = 32
        self.debug = False
        self.breakOutOfLoops = True
        self.maxLoop = 50000  # to break out of loops
        self.entryOffset = 0
        self.codeCoverage = True
        self.beginCoverage = False
        self.timelessDebugging = False  # todo: bramwell
        self.winVersion = "Windows 10"
        self.winSP = "2004"

with open(os.path.join(os.path.dirname(__file__), 'WinSysCalls.json'), 'r') as syscall_file:
    syscall_dict = json.load(syscall_file)


with open(os.path.join(os.path.dirname(__file__), 'reverseWinsysCalls.json'), 'r') as syscall_file:
    reverseSyscall_dict = json.load(syscall_file)

em = EMU()

syscallID=18
sysCallName = syscall_dict[em.winVersion][em.winSP][str(syscallID)]


print (sysCallName)

d=syscall_dict
# dict((v, k) for k, v, k in syscall_dict.items())
newDict={}
t=0
tempDictOuter0={}

for k, v in syscall_dict.items():
	# print (k)

	if t<330:
		print (v, type (v))
		tempDictOuter={}
		for p_id, p_info in v.items():
			print ("***")
			print("\nos_release:", p_id)

			tempDict={}
			for key in p_info:
				# print(key + ':', p_info[key])
				# print(p_info[key]+ ':'+ key)
				tempDict[p_info[key]] = int(key)
			# print (len(tempDict), "tempDict")
			# print (tempDict)
			tempDictOuter[p_id]=tempDict
	t+=1
	tempDictOuter0[k]=tempDictOuter

print (len(tempDictOuter0), "tempDictOuter0")
print (tempDictOuter0)
# print (newDict)
my_map=newDict

# inv_map = {v: k for k, v in newDict.items()}
# print (inv_map)

# for p_id, p_info in newDict.items():
# 	print ("***")
# 	print("\nos_release:", p_id)

# 	for key in p_info:
# 		print(key + ':', p_info[key])
# 		print(p_info[key]+ ':'+ key)


string1="""random line
random line
pop eax
pop edi
"""

random2="""pop edx
"""

# print (string1+random2)

# inv_map = dict(zip(newDict.values(), newDict.keys()))

print (em.winVersion, em.winSP)
sysCallName = reverseSyscall_dict[em.winVersion][em.winSP]["NtAllocateVirtualMemory"]
print (sysCallName)
