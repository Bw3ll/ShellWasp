import os
import json
from .syscall_signatures import *
from .ui import *

from keystone import *
from binascii import hexlify
from .parseconf import *
import colorama
import sys
import ast
import traceback
import re
colorama.init()


red ='\u001b[31;1m'
gre = '\u001b[32;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'
res2 = '\u001b[0m'

oldsysOut=sys.stdout
my_stdout = open( 1, "w", buffering = 400000 )

sys.stdout = my_stdout
sys.stdout=oldsysOut

configOptions={}
class shellcode():
    def __init__(self):
        self.osChoices = []
        self.show_comments = True
        self.printStringLiteral = True
        self.osChoices2 = []
        self.list_of_syscalls=[]

class configOpt():
	def __init__(self):
		self.r22H2=False
		self.r21H2 =False
		self.r21H1 =False
		self.r20H2 =False
		self.r2004 =False
		self.r1909 =False
		self.r1903 =False
		self.r1809 =False
		self.r1803 =False
		self.r1709 =False
		self.r1703 =False
		self.r1607 =False
		self.r1511 =False
		self.r1507 =False
		self.b21H2 = False
		self.b22H2 = False

	
class winReleases():		
	def __init__(self):
		# self.win10ReverseLookup={"19044":"21H2", "19043":"21H1", "19042":"20H2", "19041":"2004", "18363":"1909", "18362":"1903", "17763":"1809", "17134":"1803", "16299":"1709", "15063":"1703", "14393":"1607", "10586":"1511", "10240":"1507"}
		self.win10ReverseLookup={"19044":"21H2, Win10", "19043":"21H1, Win10", "19042":"20H2, Win10", "19041":"2004, Win10", "18363":"1909, Win10", "18362":"1903, Win10", "17763":"1809, Win10", "17134":"1803, Win10", "16299":"1709, Win10", "15063":"1703, Win10", "14393":"1607, Win10", "10586":"1511, Win10", "10240":"1507"}
		self.win10ReverseLookupHex={"4A64": "21H2", "4A65": "22H2", "4A63": "21H1", "4A62": "20H2", "4A61": "2004", "47BB": "1909", "47BA": "1903", "4563": "1809", "42EE": "1803", "3FAB": "1709", "3AD7": "1703", "3839": "1607", "295A": "1511", "2800": "1507"}
		# Win11 21H2 build 22000 55F0
		self.win11ReverseLookupHex={"55F0":"21H2", "585D":"22H2"}
		self.win11ReverseLookup={"22000":"21H2, Win11", "22621":"22H2, Win11"}
		self.winOSReverseLookupHex={"4A64": "Windows 10","4A65": "Windows 10", "4A63": "Windows 10", "4A62": "Windows 10", "4A61": "Windows 10", "47BB": "Windows 10", "47BA": "Windows 10", "4563": "Windows 10", "42EE": "Windows 10", "3FAB": "Windows 10", "3AD7": "Windows 10", "3839": "Windows 10", "295A": "Windows 10", "2800": "Windows 10", "55F0":"Windows 11","585D":"Windows 11", "1DB0":"Windows 7", "1DB1":"Windows 7", "4F7C":"Windows Server 2022"}
		self.winOSReverseLookup={"4A64":"Windows 10", "4A65": "Windows 10", "21H1":"Windows 10", "20H2":"Windows 10", "2004":"Windows 10", "1909":"Windows 10", "1903":"Windows 10", "1809":"Windows 10", "1803":"Windows 10", "1709":"Windows 10", "1703":"Windows 10", "1607":"Windows 10", "1511":"Windows 10", "1507":"Windows 10","1DB0":"Windows 7", "1DB1":"Windows 7", "4F7C":"Windows Server 2022","55F0":"Windows 11", "585D":"Windows 11"}
		self.win10ReverseLookupBackup={"4A64":"21H2", "4A65":"22H2","21H1":"21H1", "20H2":"20H2", "2004":"2004", "1909":"1909", "1903":"1903", "1809":"1809", "1803":"1803", "1709":"1709", "1703":"1703", "1607":"1607", "1511":"1511", "1507":"1507"}

		# Windows Server 2022 build 20348 4F7C
		# Windows 7 Sp0 7600 1DB0
		# Windows 7 Sp1 7601 1DB1
		self.win7ReverseLookupHex={"1DB0":"SP0", "1DB1":"SP1"}
		self.win7ReverseLookup={"7600":"Win7, Sp0", "7601":"Win7, Sp1"}
		self.winServer22ReverseLookupHex={"4F7C":"20348, Windows Server 2022"}
		self.winOSBoolSelected={"4A64": False, "4A65": False, "4A63": False, "4A62": False, "4A61": False, "47BB": False, "47BA": False, "4563": False, "42EE": False, "3FAB": False, "3AD7": False, "3839": False, "295A": False, "2800": False, "55F0":False,  "585D":False,"1DB0":False, "1DB1":False, "4F7C":False}
		self.releaseOptions={"r14":"4A65","r13":"4A64", "r12":"21H1", "r11":"20H2", "r10":"2004", "r9":"1909", "r8":"1903", "r7":"1809", "r6":"1803", "r5":"1709", "r4":"1703", "r3":"1607", "r2":"1511", "r1":"1507", "sp1":"1DB1", "sp0":"1DB0", "b1":"55F0", "b2":"585D"}
		self.osChoiceToHex={"4A64":"4A64","4A65":"4A65", "21H1":"4A63", "20H2":"4A62", "2004":"4A61", "1909":"47BB", "1903":"47BA", "1809":"4563", "1803":"42EE", "1709":"3FAB", "1703":"3AD7", "1607":"3839", "1511":"295A", "1507":"2800", "1DB1":"1DB1", "1DB0":"1DB0", "55F0":"55F0", "585D":"585D"}
		self.listWin7Vals=["1DB0", "1DB1"]
		self.listWin1011Vals=["4A64", "4A65","21H1","20H2","2004","1909","1903","1809","1803","1709","1703","1607","1511","1507","55F0", "585D"]


class winSyscalls():
	def __init__(self):
		with open(os.path.join(os.path.dirname(__file__), 'WinSysCalls.json'), 'r') as syscall_file:
			self.syscall_dict = json.load(syscall_file)
		with open(os.path.join(os.path.dirname(__file__), 'reverseWinsysCallsInt.json'), 'r') as syscall_file:
			self.reverseSyscall_dict = json.load(syscall_file)

class shellBytes:
	def __init__(self):
		self.stringLiteral=""
		self.shellcode=[]
		self.count=0
		self.bytesShellcode=""
		self.shellCodeStrLit=""
# with open(os.path.join(os.path.dirname(__file__), 'syscall_signatures.json'), 'r') as syscall_file:
#     syscallPrototypes = json.load(syscall_file)

conFile = str("config.cfg")

def checkWinOSBools():
	builds.winOSBoolSelected["4A64"]=False
	builds.winOSBoolSelected["4A65"]=False
	builds.winOSBoolSelected["21H1"]=False
	builds.winOSBoolSelected["20H2"]=False
	builds.winOSBoolSelected["2004"]=False
	builds.winOSBoolSelected["1909"]=False
	builds.winOSBoolSelected["1903"]=False
	builds.winOSBoolSelected["1809"]=False
	builds.winOSBoolSelected["1803"]=False
	builds.winOSBoolSelected["1709"]=False
	builds.winOSBoolSelected["1703"]=False
	builds.winOSBoolSelected["1607"]=False
	builds.winOSBoolSelected["1511"]=False
	builds.winOSBoolSelected["1507"]=False
	builds.winOSBoolSelected["1DB0"]=False
	builds.winOSBoolSelected["1DB1"]=False
	builds.winOSBoolSelected["55F0"]=False
	builds.winOSBoolSelected["58FD"]=False


	for myOs in sh.osChoices2:
		builds.winOSBoolSelected[myOs]=True

def readConf():
	con = Configuration(conFile)
	conr = con.readConf()
	r22H2= conr.getboolean('Windows 10','r22H2')
	builds.winOSBoolSelected["4A65"]=r22H2
	r21H2= conr.getboolean('Windows 10','r21H2')
	builds.winOSBoolSelected["4A64"]=r21H2
	r21H1= conr.getboolean('Windows 10','r21h1')
	builds.winOSBoolSelected["21H1"]=r21H1
	r20H2= conr.getboolean('Windows 10','r20h2')
	builds.winOSBoolSelected["20H2"]=r20H2
	r2004= conr.getboolean('Windows 10','r2004')
	builds.winOSBoolSelected["2004"]=r2004
	r1909= conr.getboolean('Windows 10','r1909')
	builds.winOSBoolSelected["1909"]=r1909
	r1903= conr.getboolean('Windows 10','r1903')
	builds.winOSBoolSelected["1903"]=r1903
	r1809= conr.getboolean('Windows 10','r1809')
	builds.winOSBoolSelected["1809"]=r1809
	r1803= conr.getboolean('Windows 10','r1803')
	builds.winOSBoolSelected["1803"]=r1803
	r1709= conr.getboolean('Windows 10','r1709')
	builds.winOSBoolSelected["1709"]=r1709
	r1703= conr.getboolean('Windows 10','r1703')
	builds.winOSBoolSelected["1703"]=r1703
	r1607= conr.getboolean('Windows 10','r1607')
	builds.winOSBoolSelected["1607"]=r1607
	r1511= conr.getboolean('Windows 10','r1511')
	builds.winOSBoolSelected["1511"]=r1511
	r1507= conr.getboolean('Windows 10','r1507')
	builds.winOSBoolSelected["1507"]=r1507

	Win7SP0=conr.getboolean('Windows 7','SP0')
	builds.winOSBoolSelected["1DB0"]=Win7SP0

	Win7SP1=conr.getboolean('Windows 7','SP1')
	builds.winOSBoolSelected["1DB1"]=Win7SP1
	

	Win11_21H2=conr.getboolean('Windows 11','b21H2')
	builds.winOSBoolSelected["55F0"]=Win11_21H2

	Win11_22H2=conr.getboolean('Windows 11','b22H2')
	builds.winOSBoolSelected["585D"]=Win11_22H2

	sh.printStringLiteral=conr.getboolean('MISC','print_string_literal_of_bytes')
	sh.show_comments=conr.getboolean('MISC','show_comments')
	# print (red+str(sh.show_comments)+res, "sh.show_comments")
	if r22H2:
		sh.osChoices2.append("4A65")
	if r21H2:
		sh.osChoices2.append("4A64")
	if r21H1:
		sh.osChoices2.append("21H1")
	if r20H2:
		sh.osChoices2.append("20H2")
	if r2004:
		sh.osChoices2.append("2004")
	if r1909:
		sh.osChoices2.append("1909")
	if r1903:
		sh.osChoices2.append("1903")
	if r1809:
		sh.osChoices2.append("1809")
	if r1803:
		sh.osChoices2.append("1803")
	if r1709:
		sh.osChoices2.append("1709")
	if r1703:
		sh.osChoices2.append("1703")
	if r1607:
		sh.osChoices2.append("1607")
	if r1511:
		sh.osChoices2.append("1511")
	if r1507:
		sh.osChoices2.append("1507")
	if Win7SP0:
		sh.osChoices2.append("1DB0")
	if Win7SP1:
		sh.osChoices2.append("1DB1")
	if Win11_21H2:
		sh.osChoices2.append("55F0")
	if Win11_22H2:
		sh.osChoices2.append("585D")


	# print ("sh.osChoices2!!!")
	# print (sh.osChoices2)

	sh.list_of_syscalls = str(conr['SYSCALLS']['selected_syscalls'])

	try:
		sh.list_of_syscalls = ast.literal_eval(sh.list_of_syscalls)
		if(type(sh.list_of_syscalls) != list):
			print("Error:", sh.list_of_syscalls, "<-- this should be in list format.")
	except:
		print(yel + "The value of", red + sh.list_of_syscalls, yel + "is not correct or malformed!!"+ res)
		sys.exit()

	sanitizeSyscalls()


	# print ("listofSyscalls", sh.list_of_syscalls)
def sanitizeSyscallsAdded(tempSys2):
	addedSyscalls=[]
	for term  in tempSys2:
		if term.lower() in syscallLowerLookupDict:
			term=syscallLowerLookupDict[term.lower()]
			addedSyscalls.append(term)
	return addedSyscalls
			

def sanitizeSyscalls():
	t=0
	for term in sh.list_of_syscalls:
		if term.lower() in syscallLowerLookupDict:
			term=syscallLowerLookupDict[term.lower()]
			sh.list_of_syscalls[t]=term
		else:
			print (red+"The " +yel + term +red + " syscall is not present. Check spelling. Item removed."+res)
			del sh.list_of_syscalls[t]
		t+=1
def saveConf(con):
	global configOptions
	try:
		con.changeConf(configOptions)
		con.save()
		print(gre + "\tConfiguration has been Saved.\n" + res)
	except Exception as e:
		print(red + "\tCould not save configuration." + res, e)
		print(traceback.format_exc())


def modConf():
	global configOptions
	# self.winOSBoolSelected={"4A64": False, "4A63": False, "4A62": False, "4A61": False, "47BB": False, "47BA": False, "4563": False, "42EE": False, "3FAB": False, "3AD7": False, "3839": False, "295A": False, "2800": False, "55F0":False, "1DB0":False, "1DB1":False, "4F7C":False}
	# listofStrings = ['pushret', 
	# 			'callpop', 
	# 			'fstenv', 
	# 			'syscall', 
	# 			'heaven', 
	# 			'peb', 
	# 			'disassembly', 
	# 			'pebpresent', 
	# 			'bit32',
	# 			'max_bytes_forward',
	# 			'max_bytes_backward',
	# 			'max_lines_forward', 
	# 			'max_lines_backward',
	# 			'print_to_screen', 
	# 			'push_stack_strings', 
	# 			'ascii_strings', 
	# 			'wide_char_strings', 
	# 			'fast_mode', 
	# 			'find_all', 
	# 			'dist_mode', 
	# 			'cpu_count', 'nodes_file', 'output_file', 'dec_operation_type', 'decrypt_file', 'stub_file', 'use_same_file', 'stub_entry_point', 'stub_end', 'shellEntry', 'pebpoints', 'minimum_str_length', 'max_callpop_distance', 'default_outdir', 'print_emulation_result', 'emulation_verbose_mode', 'emulation_multiline','max_num_of_instr','iterations_before_break','break_infinite_loops','timeless_debugging',"complete_code_coverage"]





	# maxEmuInstr = emuObj.maxEmuInstr
	# numOfIter = emuObj.numOfIter
	# numOfIter = em.maxLoop


	# listofBools = [bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, pebPresent, bit32, bytesForward, bytesBack, linesForward, linesBack,p2screen, bPushStackStrings, bAsciiStrings, bWideCharStrings, dFastMode, dFindAll, dDistr, dCPUcount, dNodesFile, dOutputFile, decryptOpTypes, decryptFile, stubFile, sameFile, stubEntry, stubEnd, shellEntry, pebPoints, minStrLen, maxDistance, sharem_out_dir, bPrintEmulation, emulation_verbose, emulation_multiline, maxEmuInstr, numOfIter, emuObj.breakLoop, emuObj.verbose,em.codeCoverage]




	checkWinOSBools()
	r21H2 = builds.winOSBoolSelected["4A64"]
	r22H2 = builds.winOSBoolSelected["4A65"]
	r21H1 = builds.winOSBoolSelected["21H1"]
	r20H2 = builds.winOSBoolSelected["20H2"]
	r2004 = builds.winOSBoolSelected["2004"]
	r1909 = builds.winOSBoolSelected["1909"]
	r1903 = builds.winOSBoolSelected["1903"]
	r1809 = builds.winOSBoolSelected["1809"]
	r1803 = builds.winOSBoolSelected["1803"]
	r1709 = builds.winOSBoolSelected["1709"]
	r1703 = builds.winOSBoolSelected["1703"]
	r1607 = builds.winOSBoolSelected["1607"]
	r1511 = builds.winOSBoolSelected["1511"]
	r1507 = builds.winOSBoolSelected["1507"]
	sp0 = builds.winOSBoolSelected["1DB0"]
	sp1 = builds.winOSBoolSelected["1DB1"]
	b21H2 = builds.winOSBoolSelected["55F0"]
	b22H2 = builds.winOSBoolSelected["58FD"]

	

	listofStrings=["r21H2",	"r22H2", "r21h1",	"r20h2",	"r2004",	"r1909",	"r1903",	"r1809",	"r1803",	"r1709",	"r1703",	"r1607",	"r1511","r1507","sp0","sp1", "b21H2", "b22H2"]
	listofBools=[r21H2,r22H2, r21H1, r20H2, r2004, r1909, r1903, r1809, r1803, r1709, r1703, r1607, r1511, r1507,sp0,sp1,b21H2, b22H2] 

	listofStrings.append("selected_syscalls")
	listofBools.append(sh.list_of_syscalls)
	# listofSyscalls = []
	# for osv in syscallSelection:
	# 	if osv.toggle == True:
	# 		listofSyscalls.append(osv.code)
	# listofStrings.append('selected_syscalls')
	# listofBools.append(listofSyscalls)



	# for booli, boolStr in zip(listofBools, listofStrings):
	# 	configOptions[boolStr] = booli



	

	# Win7SP0=conr.getboolean('Windows 7','SP0')
	# builds.winOSBoolSelected["1DB0"]=Win7SP0

	# Win7SP1=conr.getboolean('Windows 7','SP1')
	# builds.winOSBoolSelected["1DB1"]=Win7SP1
	
	# Win11_21H2=conr.getboolean('Windows 11','r21H2')
	# builds.winOSBoolSelected["55F0"]=Win11_21H2

	# sh.printStringLiteral=conr.getboolean('MISC','print_string_literal_of_bytes')
	# sh.show_comments=conr.getboolean('MISC','show_comments')
	# maxEmuInstr = emuObj.maxEmuInstr
	# numOfIter = emuObj.numOfIter
	# numOfIter = em.maxLoop
	# listofBools = [bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, pebPresent, bit32, bytesForward, bytesBack, linesForward, linesBack,p2screen, bPushStackStrings, bAsciiStrings, bWideCharStrings, dFastMode, dFindAll, dDistr, dCPUcount, dNodesFile, dOutputFile, decryptOpTypes, decryptFile, stubFile, sameFile, stubEntry, stubEnd, shellEntry, pebPoints, minStrLen, maxDistance, sharem_out_dir, bPrintEmulation, emulation_verbose, emulation_multiline, maxEmuInstr, numOfIter, emuObj.breakLoop, emuObj.verbose,em.codeCoverage]
	# listofBools=[]
	# listofSyscalls = []
	# for osv in syscallSelection:
	# 	if osv.toggle == True:
	# 		listofSyscalls.append(osv.code)
	# listofStrings.append('selected_syscalls')
	# listofBools.append(listofSyscalls)

	
	try:
		for booli, boolStr in zip(listofBools, listofStrings):
			# print (boolStr, booli)
			if type (booli)==bool:
				booli=(str(booli))
			configOptions[boolStr] = booli
	except Exception as e:
		print (e)
		print(traceback.format_exc())
	# print (configOptions)

def isWin7():
	if any(item in builds.listWin7Vals for item in sh.osChoices2):
		# print ("WINDOWS 7!!!")
		# print (sh.osChoices2)
		return True
	else:
		return False

def isWin1011():
	if any(item in builds.listWin1011Vals for item in sh.osChoices2):
		# print ("WINDOWS 10!!!")
		# print (sh.osChoices2)
		return True
	else:
		return False

def buildSyscall():
	# osChoices = ["4A62","3AD7", "47BA","1DB0", "55F0", "4A64"]

	# syscallChoices=["NtAllocateVirtualMemory", "NtCreateKey", "NtReplaceKey","NtSetContextThread", "NtSetValueKey"]
	if len(sh.osChoices2)==0 or len(sh.list_of_syscalls)==0:
		print(red+"\tInadequate number of syscalls selections or Windows releases to continue!"+res)
		return
	osChoices=sh.osChoices2
	syscallChoices=sh.list_of_syscalls
	revSyscallChoices=syscallChoices.copy()
	revSyscallChoices.reverse()
	dictSyscallEDILocations={}
	listOfSyscallsAdded = [] # this allows only one per each, in order given!
	t=0
	for each in syscallChoices:
		if each not in dictSyscallEDILocations:
			dictSyscallEDILocations[each]=t
		t+=1
	# print ("syscallChoices")
	# print (syscallChoices)
	# print (red, "revSyscallChoices",res)
	# print (revSyscallChoices)
	# print ("dict")
	# print (dictSyscallEDILocations)
	# print ("end")

	#####
	# 21H2 build 22000 55F0

	# print (syscallChoices)
	# print ("revSyscallChoices", revSyscallChoices)

	if isWin7() and isWin1011():
		initializerStart="""mov eax, fs:[0x30]
mov ebx, [eax+0xac]
mov eax, [eax+0xa4]
mov ecx, esp
sub esp, 0x1000

"""
		endInitializer="""
saveSyscallArray:
push eax
mov edi, esp
add edi, 0x4
mov esp, ecx

"""
	else:
		initializerStart="""mov ebx, fs:[0x30]
mov ebx, [ebx+0xac]
mov ecx, esp
sub esp, 0x1000

"""
		endInitializer="""
saveSyscallArray:
mov edi, esp
mov esp, ecx

"""	
	checkOsRelease=generateInitializer=generateSyscallParams=""
	saveSyscallArray="""push edi

	"""
	com1=com2=com3="\n"
	if sh.show_comments:
		com1="\t\t; "+mag+"Syscall Function"+res+"\n"
		com2="\t\t\t; "+gre+"Windows 10/11 Syscall"+res+"\n"
		com3="\t\t\t; "+gre+"Windows 7 Syscall"+res+"\n"

	if isWin7() and  isWin1011():
		ourSyscall="\nourSyscall:"+com1
		ourSyscall+="""cmp dword ptr [edi-0x4],0xa
jne win7
"""

		ourSyscall+="\nwin10:"+com2
		ourSyscall+="""call dword ptr fs:[0xc0]
ret 
"""
		ourSyscall+="\nwin7:"+com3
		ourSyscall+="""xor ecx, ecx
lea edx, [esp+4]
call dword ptr fs:[0xc0]
add esp, 4
ret"""
	elif isWin1011():
		ourSyscall="\nourSyscall:"+com1
		ourSyscall+="""call dword ptr fs:[0xc0]
ret"""
	elif isWin7():
		ourSyscall="\nourSyscall:"+com1
		ourSyscall+="""xor ecx, ecx
lea edx, [esp+4]
call dword ptr fs:[0xc0]
add esp, 4
ret"""	
	endShellcode0="""jmp end
"""

	save="""jne win7
	win10:
	    call [fs:0xc0]
	    ret 
 	win7:
        xor ecx, ecx
        lea edx, [esp+4]
        call [fs:0xc0]
        add esp, 4
        ret"""
	endShellcode1="""

end:
nop
"""
	##########Initialize Syscall Array
	t=1
	numChoices=len(osChoices)
	for osChoice in osChoices:
		winVersion=builds.winOSReverseLookup[osChoice]

		hexOsChoice=builds.osChoiceToHex[osChoice]		
		sizeOsBuild=len(hexOsChoice)
		osBStart=sizeOsBuild-2
		osBuild=hexOsChoice[osBStart:]
		# print ("osBuild", osBuild)

		winReleaseText=""


		if sh.show_comments:
			if winVersion=="Windows 10":
				winReleaseText="; "+mag+builds.win10ReverseLookupBackup[osChoice] +", Win10 release"+res

			elif winVersion=="Windows 7":
				winReleaseText="; "+mag+builds.win7ReverseLookup[str(int(osChoice,16))] +" release"+res
			elif winVersion=="Windows 11":
				winReleaseText="; "+mag+builds.win11ReverseLookup[str(int(osChoice,16))] +" release"+res
			
		generateInitializer+="cmp bl, 0x"+osBuild+"\t\t" + winReleaseText + "\n"
		if t ==(numChoices):
			generateInitializer+="jl end"  +"\n"
		else:
			generateInitializer+="jl less" +str(t) +"\n"



		for mySyscall in syscallChoices:
			# winVersion=winOSReverseLookupHex[osChoice]
			if mySyscall not in listOfSyscallsAdded:
				listOfSyscallsAdded.append(mySyscall)
				if winVersion=="Windows 10":
					winRelease=builds.win10ReverseLookupBackup[osChoice]
				elif winVersion=="Windows 7":
					winRelease=builds.win7ReverseLookupHex[osChoice]
				elif winVersion=="Windows 11":
					winRelease=builds.win11ReverseLookupHex[osChoice]

				# winRelease2=builds.win11ReverseLookupHex["ntallocatevirtualmemory"].casefold()
			
				# print ("winRelease", winRelease)
				mySyscallComment=""
				if sh.show_comments:
					mySyscallComment= "; "+ gre+mySyscall+res
				# print ("winRelease", winRelease, osChoice)
				temp="push " + hex(syscalls.reverseSyscall_dict[winVersion][winRelease][mySyscall]) + "\t\t" + mySyscallComment+"\n"
				# print (temp)
				generateInitializer+=temp
		# generateInitializer+="jmp done\n"
				
		if t !=(numChoices):
			generateInitializer+="jmp saveSyscallArray\nless" +str(t)+":\n"

		t+=1
		revlistOfSyscallsAdded=listOfSyscallsAdded.copy()
		revlistOfSyscallsAdded.reverse()
		listOfSyscallsAdded.clear()	
		wt=0
		for each in revlistOfSyscallsAdded:
			dictSyscallEDILocations[each]=wt
			wt+=1
	##################################
	# z=0


	for mySyscall in syscallChoices:
		sysPrototype= (syscall_signature[mySyscall])
		numSyscallParams=sysPrototype[0]
		t=numSyscallParams-1
		generateSyscallParams+="push edi\n"
		for each in range(numSyscallParams):
			temp="push 0x00000000 ; param " + str(t)
			commentSyscallParams=""
			if sh.show_comments:
				commentSyscallParams="; " + cya+ sysPrototype[1][t] + " " + yel+  sysPrototype[2][t] +res
			generateSyscallParams+="push 0x00000000 \t" +  commentSyscallParams +"\n"
			t-=1
		generateSyscallParams+="\n"
		syscallComment=""
		z = dictSyscallEDILocations[mySyscall]
		if sh.show_comments:
			syscallComment="; " +gre+ mySyscall + " syscall"+res
		if z==0:
			generateSyscallParams+="mov eax, [edi]\t\t"+syscallComment+"\ncall ourSyscall\n\n"
		else:
			generateSyscallParams+="mov eax, [edi+"+hex(z*4)+"]\t"+syscallComment+"\ncall ourSyscall\n\n"
		# z+=1

		stackCleanupRestore="mov edi, [esp+" + hex(numSyscallParams*4) + "]\n\n"
		# stackCleanupRestore="add esp, " + hex(numSyscallParams*4) + "\n"  // DEPRECATED
		# stackCleanupRestore+="pop edi\n\n"  // DEPRECATED
		#### mov edi, [esp+0x] provides greater stability for a shellcode with a longer sequence of syscalls. 
		generateSyscallParams +=stackCleanupRestore

	# print (win10ReverseLookup["15063"])

	# print (hex(sysCallName))

	print ("\n\n\n")
	finalSyscallShellcode= (initializerStart+generateInitializer+endInitializer+generateSyscallParams+ endShellcode0+ ourSyscall + endShellcode1)
	print (finalSyscallShellcode)
	finalSyscallShellcode = finalSyscallShellcode.replace(gre,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(res,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(mag,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(yel,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(blu,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(res,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(cya,'')
	finalSyscallShellcodeText=finalSyscallShellcode
	finalSyscallShellcode = finalSyscallShellcode.replace(';','#')
	# print (finalSyscallShellcodeText)

	#generate bytes
	generateBytes(finalSyscallShellcode)
	
	if sh.printStringLiteral:
		print(sRaw.bytesShellcode)

		print(sRaw.shellCodeStrLit)



SYSCALL_BOOL_DICT = {
"l": False,
"d": False,
"D": False,
"all": False,
"xp": False,
"xp1": False,
"xp2": False,
"s3": False,
"s30": False,
"s32": False,
"s3r": False,
"s3r2": False,
"v": False,
"v0": False,
"v1": False,
"v2": False,
"s8": False,
"s80": False,
"s82": False,
"s8r": False,
"s8r1": False,
"w7": False,
"w70": False,
"w71": False,
"s12": False,
"s120": False,
"s12r": False,
"w8": False,
"w80": False,
"w81": False,
"w10": False,
"r0": False,
"r1": False,
"r2": False,
"r3": False,
"r4": False,
"r5": False,
"r6": False,
"r7": False,
"r8": False,
"r9": False,
"r10": False}
def uiAddWinReleases():
	# self.win10ReverseLookup={"19044":"21H2, Win10", "19043":"21H1, Win10", "19042":"20H2, Win10", "19041":"2004, Win10", "18363":"1909, Win10", "18362":"1903, Win10", "17763":"1809, Win10", "17134":"1803, Win10", "16299":"1709, Win10", "15063":"1703, Win10", "14393":"1607, Win10", "10586":"1511, Win10", "10240":"1507"}
	checkWinOSBools()
	print (cya+"\nWindows 10:\t\t\t\tWindows 7:"+res)
	listWin10=["22H2", "21H2", "21H1", "20H2", "2004", "1909", "1903", "1809", "1803", "1709", "1703", "1607", "1511", "1507"]
	listWin10Back=["4A65", "4A64", "21H1", "20H2", "2004", "1909", "1903", "1809", "1803", "1709", "1703", "1607", "1511", "1507"]

	listWin11=["22H2","21H2"]
	listWin11Back=["585D", "55F0"]

	listWin7=["SP1", "SP0"]
	listWin7Back=["1DB1","1DB0"]
	
	listWin10Codes=["r14", "r13", "r12", "r11", "r10", "r9", "r8", "r7", "r6", "r5", "r4", "r3", "r2", "r1"]
	listWin7Codes=["sp1", "sp0"]
	listWin11Codes=["b2", "b1"]
	text=""
	t=0
	stop=0
	totalWin10=len(listWin10)
	remaining=totalWin10
	for x in range(2):
		winlookUp=listWin10Back[t]
		if (builds.winOSBoolSelected[winlookUp]):
			t1="X"
		else:
			t1=" "
		winlookUp=listWin7Back[t]
		if (builds.winOSBoolSelected[winlookUp]):
			t2="X"
		else:
			t2=" "
		win10TogBool=res+"["+gre+t1+res+"]"
		win7TogBool=res+"["+gre+t2+res+"]"

		text += "\t{}\t{}\t{}\t\t\t{}\t{}\t{}\n".format(yel+listWin10Codes[t]+res, listWin10[t],win10TogBool, yel+listWin7Codes[t]+res, listWin7[t],win7TogBool)
		t+=1

	for x in range(1):
		winlookUp=listWin10Back[t]
		if (builds.winOSBoolSelected[winlookUp]):
			t1="X"
		else:
			t1=" "
		win10TogBool=res+"["+gre+t1+res+"]"
		text += "\t{}\t{}\t{}\t\t{}\t\n".format(yel+listWin10Codes[t]+res, listWin10[t],win10TogBool, cya+"Windows 11:"+res)
		t+=1
	
	w=0
	for x in range(2):
		winlookUp=listWin10Back[t]
		if (builds.winOSBoolSelected[winlookUp]):
			t1="X"
		else:
			t1=" "
		winlookUp=listWin11Back[w]
		if (builds.winOSBoolSelected[winlookUp]):
			t2="X"
		else:
			t2=" "

		win10TogBool=res+"["+gre+t1+res+"]"
		win11TogBool=res+"["+gre+t2+res+"]"

		text += "\t{}\t{}\t{}\t\t\t{}\t{}\t{}\n".format(yel+listWin10Codes[t]+res, listWin10[t],win10TogBool, yel+listWin11Codes[w]+res, listWin11[w],win11TogBool)
		t+=1	
		w+=1
	for x in range(9):
		winlookUp=listWin10Back[t]
		if (builds.winOSBoolSelected[winlookUp]):
			t1="X"
		else:
			t1=" "
		win10TogBool=res+"["+gre+t1+res+"]"
		text += "\t{}\t{}\t{}\t\t\t\n".format(yel+listWin10Codes[t]+res, listWin10[t],win10TogBool)
		t+=1	
	
	text += "  {}        \n".format(cya + "c"+res+" -"+yel+"  Clear current selections."+ res)

	print (text)
	print("  This will add to existing Windows releases. \n")

	print("  Enter the above Windows release codes in yellow. Separate each release with a "+red+"newline"+res+".\n")
	print("  Type"+red+ " q " +res+"or "+red+ " x " +res+"on a single line to end input.\n")

	while True:
		print (yel+ " SysShellcode>" + cya + "WinReleases>" + res+ red + "Input>" +  res, end="")
		
		# x = sys.stdin.read()
		ans=[]
		for line in sys.stdin:

			if 'q' == line.rstrip() or 'x' == line.rstrip():
				break
			ans.append(line.rstrip())
		# print(f'Input : {line}')
		# print (ans)

		for ch in ans:
			try:
				possible = builds.releaseOptions[ch]
				if possible not in sh.osChoices2:
					if possible != "21H3":
						sh.osChoices2.append(possible)
						winVersion=builds.winOSReverseLookup[possible]
						print ("\t"+cya+winVersion+": " + possible + " has been added.")
					else:
						print (red+"21H3 is not supported at this time."+res)
			except:
				print (red+ch+" was not accepted. Check spelling."+res)
		# sanitizeSyscalls()
		checkWinOSBools()

		break

def uiAddSyscalls():
	print("  This will add to existing syscalls present. Syscalls may be called more than once.\n")

	print("  Enter syscalls below. Selections are case insensitive. Separate each syscall with a "+red+"newline"+res+".\n")
	print("  Type"+red+ " q " +res+"or "+red+ " x " +res+"on a single line to end input.\n")

	while True:
		print (yel+ " SysShellcode>" + cya + "Syscalls>" + res+ red + "Input>" +  res, end="")
		
		# x = sys.stdin.read()
		ans=[]
		tempSys=[]
		tempSys.clear()
		for line in sys.stdin:

			if 'q' == line.rstrip() or 'x' == line.rstrip():
				break
			ans.append(line.rstrip())
			tempSys.append(line.rstrip())
			# tempSys.add(line.rstrip())
		# print(f'Input : {line}')
		# print (ans)
		sh.list_of_syscalls.extend(ans)
		sanitizeSyscalls()
		tempSys2=sanitizeSyscallsAdded(tempSys)

		print (cya+"Syscalls added:")
		for each in tempSys2:
			print ("\t",each)
		break
# print("Exit")

def uiShowWinReleases(number=None):
	# self.win10ReverseLookup={"19044":"21H2, Win10", "19043":"21H1, Win10", "19042":"20H2, Win10", "19041":"2004, Win10", "18363":"1909, Win10", "18362":"1903, Win10", "17763":"1809, Win10", "17134":"1803, Win10", "16299":"1709, Win10", "15063":"1703, Win10", "14393":"1607, Win10", "10586":"1511, Win10", "10240":"1507"}
	# 	self.win10ReverseLookupHex={"4A64": "21H2", "4A63": "21H1", "4A62": "20H2", "4A61": "2004", "47BB": "1909", "47BA": "1903", "4563": "1809", "42EE": "1803", "3FAB": "1709", "3AD7": "1703", "3839": "1607", "295A": "1511", "2800": "1507"}
	# 	# Win11 21H2 build 22000 55F0
	# 	self.win11ReverseLookupHex={"55F0":"21H2"}
	# 	self.win11ReverseLookup={"22000":"21H2, Win11"}
	# 	self.winOSReverseLookupHex={"4A64": "Windows 10", "4A63": "Windows 10", "4A62": "Windows 10", "4A61": "Windows 10", "47BB": "Windows 10", "47BA": "Windows 10", "4563": "Windows 10", "42EE": "Windows 10", "3FAB": "Windows 10", "3AD7": "Windows 10", "3839": "Windows 10", "295A": "Windows 10", "2800": "Windows 10", "55F0":"Windows 11", "1DB0":"Windows 7", "1DB1":"Windows 7", "4F7C":"Windows Server 2022"}
	# 	# Windows Server 2022 build 20348 4F7C
	# 	# Windows 7 Sp0 7600 1DB0
	# 	# Windows 7 Sp1 7601 1DB1
	# 	self.win7ReverseLookupHex={"1DB0":"SP0", "1DB1":"SP1"}
	# 	self.win7ReverseLookup={"7600":"Win7, Sp0", "7601":"Win7, Sp1"}
	# 	self.winServer22ReverseLookupHex={"4F7C":"20348, Windows Server 2022"}
	if number==None:
		print ("\tCurrent Windows release selections:")
		for osChoice in sh.osChoices2:
			winRelease=""
			winVersion=builds.winOSReverseLookup[osChoice]
			if winVersion=="Windows 10":
				winRelease=builds.win10ReverseLookupBackup[osChoice]
			elif winVersion=="Windows 7":
				winRelease=builds.win7ReverseLookupHex[osChoice]
			elif winVersion=="Windows 11":
				winRelease=builds.win11ReverseLookupHex[osChoice]

			print ("\t",gre +osChoice+res+"\t", winVersion,"\t",winRelease )
	elif number=="edit":
		print ("\tCurrent Windows release selections:")
		
		t=0
		for osChoice in sh.osChoices2:
			winRelease=""
			winVersion=builds.winOSReverseLookup[osChoice]
			if winVersion=="Windows 10":
				winRelease=builds.win10ReverseLookupBackup[osChoice]
			elif winVersion=="Windows 7":
				winRelease=builds.win7ReverseLookupHex[osChoice]
			elif winVersion=="Windows 11":
				winRelease=builds.win11ReverseLookupHex[osChoice]

			print ("\t",cya+str(t),"\t",gre +osChoice+res+"\t", winVersion,"\t",winRelease )
			t+=1


def uiShowSyscalls(number=None):
	if number==None:
		print ("\tCurrent Syscall Selections:")
		for each in sh.list_of_syscalls:
			print ("\t",gre +each+res)
	elif number=="edit":
		print ("\tCurrent Syscall Selections:")
		t=0
		for each in sh.list_of_syscalls:
			print ("\t",cya+str(t),"\t", gre +each+res)
			t+=1

def uiRearrangeSyscalls():
	uiShowSyscalls("edit")
	
	print("  Enter desired order of syscalls to appear in the shellcode, one per line.\n")
	print("  Syscalls not listed are removed. Syscalls can be used more than once.\n")

	
	print("  Type"+red+ " q " +res+"or "+red+ " x " +res+"on a single line to end input.\n")
	
	while True:
		print (yel+ " SysShellcode>" + cya + "Syscalls>" + res+ red + "Rearrange>" +  res, end="")
		
		# x = sys.stdin.read()
		ans=[]
		for line in sys.stdin:

			if 'q' == line.rstrip() or 'x' == line.rstrip():
				break
			ans.append(int(line.rstrip()))
		# print(f'Input : {line}')
		# print (ans)
		temp=	sh.list_of_syscalls.copy()
		sh.list_of_syscalls.clear()
		for new in ans:
			try:
				new=temp[new]
				sh.list_of_syscalls.append(new)
			except:
				print (red+"\t"+str(new)+" is not valid input."+res)
		print("\t"+cya+"Syscalls have been rearranged.\n"+res)
		uiShowSyscalls()
		break
def uiEditWinReleases():
	uiShowWinReleases("edit")
	
	print("  Enter the numbers corresponding to each Windows release to be removed, one per line.\n")
	
	print("  Type"+red+ " q " +res+"or "+red+ " x " +res+"on a single line to end input.\n")
	
	while True:
		print (yel+ " SysShellcode>" + cya + "WinReleases>" + res+ red + "Edit>" +  res, end="")
		
		# x = sys.stdin.read()
		ans=[]
		for line in sys.stdin:

			if 'q' == line.rstrip() or 'x' == line.rstrip():
				break
			try:
				ans.append(int(line.rstrip()))
			except:
				print(red+line.rstrip() + " is not an integer."+res)
			
				# print(traceback.format_exc())
		# print(f'Input : {line}')
		# print (ans)
		# print(sh.osChoices2)
		temp=	sh.osChoices2.copy()
		
		# print ("ans", ans)
		for removeMe in ans:
			try:
				destroy=temp[removeMe]
				sh.osChoices2.remove(destroy)
				print("\t"+cya+destroy+" has been removed."+res)
			except:
				print ("\t"+red+str(removeMe) +" is not valid input."+res)
			
				# print(traceback.format_exc())
		# print (sh.osChoices2)
		break

def uiEditSyscalls():
	uiShowSyscalls("edit")

	
	print("  Enter the numbers corresponding to each syscall to be removed, one per line.\n")
	
	print("  Type"+red+ " q " +res+"or "+red+ " x " +res+"on a single line to end input.\n")
	
	while True:
		print (yel+ " SysShellcode>" + cya + "Syscalls>" + res+ red + "Edit>" +  res, end="")
		
		# x = sys.stdin.read()
		ans=set()
		for line in sys.stdin:

			if 'q' == line.rstrip() or 'x' == line.rstrip():
				break
			try:
				ans.add(int(line.rstrip()))
			except:
				print ("\n"+red+ line.rstrip()+" is not a valid integer."+res)
		# print(f'Input : {line}')
		# print (ans)
		temp=	sh.list_of_syscalls.copy()
		
		for removeMe in ans:
			try:
				destroy=temp[removeMe]
				sh.list_of_syscalls.remove(destroy)
				print("\t"+cya+destroy + " has been removed."+res)

			except:
				try:
					print("\t"+red+removeMe + " is not valid input."+res)
				except:
					print("\t"+red+str(removeMe) + " is not valid input."+res)

		break

def uiShowOptionsMainMenu():
	text="\n"
	text += "  {}        \n".format(cya + "b"+res+" -"+gre+"  Build syscall shellcode."+ res)
	text += "  {}        \n".format(cya + "i"+res+" -"+gre+"  Add or modify syscalls."+ res)
	text += "  {}        \n".format(cya + "w"+res+" -"+gre+"  Add or modify Windows releases."+ res)
	text += "  {}        \n".format(cya + "c"+res+" -"+gre+"  Save config file ["+res+"config.cfg"+gre+"] with current selections."+ res)
	text += "  {}        \n".format(cya + "h"+res+" -"+gre+"  Display options."+ res)

	print (text)

def uiShowOptionsSyscallSelections():
	text="\n"
	text += "  {}        \n".format(cya + "c"+res+" -"+yel+"  Clear current selections."+ res)
	text += "  {}        \n".format(cya + "a"+res+" -"+yel+"  Add syscalls."+ res)
	text += "  {}        \n".format(cya + "s"+res+" -"+yel+"  Show current syscalls."+ res)
	text += "  {}        \n".format(cya + "e"+res+" -"+yel+"  Edit current syscalls."+ res)
	text += "  {}        \n".format(cya + "r"+res+" -"+yel+"  Rearrange syscalls."+ res)
	print (text)
def uiShowOptionsWinReleaseSelections():
	text="\n"
	text += "  {}        \n".format(cya + "c"+res+" -"+yel+"  Clear current selections."+ res)
	text += "  {}        \n".format(cya + "a"+res+" -"+yel+"  Add Windows releases."+ res)
	text += "  {}        \n".format(cya + "s"+res+" -"+yel+"  Show current Windows releases."+ res)
	text += "  {}        \n".format(cya + "e"+res+" -"+yel+"  Edit current Windows releases."+ res)
	print (text)


def giveInputWinReleases():
	uiShowWinReleases()
	uiShowOptionsWinReleaseSelections()
	while True:
		print(yel+ " SysShellcode>" + cya + "WinReleases> "+ res, end="")
		techIN = input()
		if(techIN[0:1] == "x"):
			# print("Returning to find shellcode instructions menu.\n")
			break
		elif(techIN[0:1] == "a"):
			uiAddWinReleases()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "c"):
			sh.osChoices2.clear()
			print ("\tList of Windows releases cleared.\n")
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "s"):
			uiShowWinReleases()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "e"):
			uiEditWinReleases()
		elif(techIN[0:1] == "h"):
			uiShowOptionsWinReleaseSelections()
		else:
			print("Invalid input")

def giveInput():
	uiShowSyscalls()
	uiShowOptionsSyscallSelections()	
	while True:
		print(yel+ " SysShellcode>" + cya + "Syscalls> "+ res, end="")
		techIN = input()
		if(techIN[0:1] == "x"):
			# print("Returning to find shellcode instructions menu.\n")
			break
		elif(techIN[0:1] == "a"):
			uiAddSyscalls()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "c"):
			sh.list_of_syscalls.clear()
			print ("\tSyscalls cleared.\n")
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "s"):
			uiShowSyscalls()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "e"):
			uiEditSyscalls()
		elif(techIN[0:1] == "r"):
			uiRearrangeSyscalls()
		elif(techIN[0:1] == "h"):
			uiShowOptionsSyscallSelections()
		else:
			print("Invalid input")

def generateBytes(shellInput):
	ks = Ks(KS_ARCH_X86, KS_MODE_32)
	sRaw.shellcode, sRaw.count = ks.asm(shellInput)
	sRaw.bytesShellcode=bytes(sRaw.shellcode)
	sRaw.bytesShellcode=cya+sRaw.bytesShellcode.hex()+res

	sRaw.shellCodeStrLit = 'x' + str(hexlify(bytearray(sRaw.shellcode),'x',1))[2:-1]
	sRaw.shellCodeStrLit = '"' + sRaw.shellCodeStrLit.replace('x','\\x') + '"'
	sRaw.shellCodeStrLit = blu+ sRaw.shellCodeStrLit+res
def ui():
	splash()
	showOptions()
	uiShowOptionsMainMenu()
	x = ""

	while x != "e":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " SysShellcode> " + res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "x":
				print("\nExiting program.\n")
				break
			
			elif userIN[0:1] == "i":
				giveInput()
			elif userIN[0:1] == "b":
				buildSyscall()
			elif userIN[0:1] == "s":	# "find assembly instrucitons associated with shellcode"
				pass
			elif userIN[0:1] == "w":
				giveInputWinReleases()
			elif(re.match("^b$", userIN)):
				pass
			elif userIN[0:1] == "U" or userIN[0:1] == "u":                  
				pass
			elif userIN[0:1] == "a":	# "change architecture, 32-bit or 64-bit"
				# print("\nReturning to main menu.\n")
				pass
			elif(re.match("^c$", userIN)):   # "save configuration"
				con = Configuration(conFile)

				# print("trying to save!")
				modConf()
				saveConf(con)
			elif userIN[0:1] == "h":
				uiShowOptionsMainMenu()

			else:
				print("\nInvalid input.\n")

		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")

def syscallMain():
	readConf()
	# buildSyscall()
	ui()
sConf=configOpt()
sh = shellcode()
builds=winReleases()
syscalls=winSyscalls()
sRaw=shellBytes()