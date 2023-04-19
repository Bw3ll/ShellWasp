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
import datetime
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
		self.style="fs"
		self.intendedCompiler="nasm"
		self.useSharedData=True
		self.user12Teb=True
		self.encodeUSD=False
		self.encodeUSDKey=0x909
		self.addUSD=True
		self.addUSDVal=0x20345242
	def style(self):
		return self.style
	def comp(self):
		return self.intendedCompiler
	def setStyle(self,style):
		self.style=style
	def setComp(self,comp):
		self.intendedCompiler=comp

class configOpt():
	def __init__(self):
		self.r22h2=False
		self.r21h2 =False
		self.r21h1 =False
		self.r20h2 =False
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
		self.b21h2 = False
		self.b22h2 = False

	
class winReleases():		
	def __init__(self):
		# self.win10ReverseLookup={"19044":"21h2", "19043":"21h1", "19042":"20h2", "19041":"2004", "18363":"1909", "18362":"1903", "17763":"1809", "17134":"1803", "16299":"1709", "15063":"1703", "14393":"1607", "10586":"1511", "10240":"1507"}
		self.win10ReverseLookup={"19044":"21h2, Win10", "19043":"21h1, Win10", "19042":"20h2, Win10", "19041":"2004, Win10", "18363":"1909, Win10", "18362":"1903, Win10", "17763":"1809, Win10", "17134":"1803, Win10", "16299":"1709, Win10", "15063":"1703, Win10", "14393":"1607, Win10", "10586":"1511, Win10", "10240":"1507"}
		self.win10ReverseLookupHex={"4A64": "21h2", "4A65": "22h2", "4A63": "21h1", "4A62": "20h2", "4A61": "2004", "47BB": "1909", "47BA": "1903", "4563": "1809", "42EE": "1803", "3FAB": "1709", "3AD7": "1703", "3839": "1607", "295A": "1511", "2800": "1507"}
		# Win11 21h2 build 22000 55F0
		self.win11ReverseLookupHex={"55F0":"21h2", "585D":"22h2"}
		self.win11ReverseLookup={"22000":"21h2, Win11", "22621":"22h2, Win11"}
		self.winOSReverseLookupHex={"4A64": "Windows 10","4A65": "Windows 10", "4A63": "Windows 10", "4A62": "Windows 10", "4A61": "Windows 10", "47BB": "Windows 10", "47BA": "Windows 10", "4563": "Windows 10", "42EE": "Windows 10", "3FAB": "Windows 10", "3AD7": "Windows 10", "3839": "Windows 10", "295A": "Windows 10", "2800": "Windows 10", "55F0":"Windows 11","585D":"Windows 11", "1DB0":"Windows 7", "1DB1":"Windows 7", "4F7C":"Windows Server 2022"}
		self.winOSReverseLookup={"4A64":"Windows 10", "4A65": "Windows 10", "21h1":"Windows 10", "20h2":"Windows 10", "2004":"Windows 10", "1909":"Windows 10", "1903":"Windows 10", "1809":"Windows 10", "1803":"Windows 10", "1709":"Windows 10", "1703":"Windows 10", "1607":"Windows 10", "1511":"Windows 10", "1507":"Windows 10","1DB0":"Windows 7", "1DB1":"Windows 7", "4F7C":"Windows Server 2022","55F0":"Windows 11", "585D":"Windows 11"}
		self.win10ReverseLookupBackup={"4A64":"21h2", "4A65":"22h2","21h1":"21h1", "20h2":"20h2", "2004":"2004", "1909":"1909", "1903":"1903", "1809":"1809", "1803":"1803", "1709":"1709", "1703":"1703", "1607":"1607", "1511":"1511", "1507":"1507"}

		# Windows Server 2022 build 20348 4F7C
		# Windows 7 Sp0 7600 1DB0
		# Windows 7 Sp1 7601 1DB1
		self.win7ReverseLookupHex={"1DB0":"SP0", "1DB1":"SP1"}
		self.win7ReverseLookup={"7600":"Win7, Sp0", "7601":"Win7, Sp1"}
		self.winServer22ReverseLookupHex={"4F7C":"20348, Windows Server 2022"}
		self.winOSBoolSelected={"4A64": False, "4A65": False, "4A63": False, "4A62": False, "4A61": False, "47BB": False, "47BA": False, "4563": False, "42EE": False, "3FAB": False, "3AD7": False, "3839": False, "295A": False, "2800": False, "55F0":False,  "585D":False,"1DB0":False, "1DB1":False, "4F7C":False}
		self.releaseOptions={"r14":"4A65","r13":"4A64", "r12":"21h1", "r11":"20h2", "r10":"2004", "r9":"1909", "r8":"1903", "r7":"1809", "r6":"1803", "r5":"1709", "r4":"1703", "r3":"1607", "r2":"1511", "r1":"1507", "sp1":"1DB1", "sp0":"1DB0", "b1":"55F0", "b2":"585D"}
		self.osChoiceToHex={"4A64":"4A64","4A65":"4A65", "21h1":"4A63", "20h2":"4A62", "2004":"4A61", "1909":"47BB", "1903":"47BA", "1809":"4563", "1803":"42EE", "1709":"3FAB", "1703":"3AD7", "1607":"3839", "1511":"295A", "1507":"2800", "1DB1":"1DB1", "1DB0":"1DB0", "55F0":"55F0", "585D":"585D"}
		self.listWin7Vals=["1DB0", "1DB1"]
		self.listWin1011Vals=["4A64", "4A65","21h1","20h2","2004","1909","1903","1809","1803","1709","1703","1607","1511","1507","55F0", "585D"]


class winSyscalls():
	def __init__(self):
		with open(os.path.join(os.path.dirname(__file__), 'WinSysCalls.json'), 'r') as syscall_file:
			self.syscall_dict = json.load(syscall_file)
		with open(os.path.join(os.path.dirname(__file__), 'reverseWinSyscallsInt.json'), 'r') as syscall_file:
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
	# print ("builds.winOSBoolSelected", builds.winOSBoolSelected)
	builds.winOSBoolSelected["4A64"]=False
	builds.winOSBoolSelected["4A65"]=False
	builds.winOSBoolSelected["21h1"]=False
	builds.winOSBoolSelected["20h2"]=False
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
	builds.winOSBoolSelected["585D"]=False


	# print ("current choices", sh.osChoices2)
	for myOs in sh.osChoices2:
		builds.winOSBoolSelected[myOs]=True


def readConf():
	con = Configuration(conFile)
	conr = con.readConf()
	r22h2= conr.getboolean('Windows 10','r22h2')
	builds.winOSBoolSelected["4A65"]=r22h2
	r21h2= conr.getboolean('Windows 10','r21h2')
	builds.winOSBoolSelected["4A64"]=r21h2
	r21h1= conr.getboolean('Windows 10','r21h1')
	builds.winOSBoolSelected["21h1"]=r21h1
	r20h2= conr.getboolean('Windows 10','r20h2')
	builds.winOSBoolSelected["20h2"]=r20h2
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
	

	Win11_21h2=conr.getboolean('Windows 11','b21h2')
	builds.winOSBoolSelected["55F0"]=Win11_21h2

	Win11_22h2=conr.getboolean('Windows 11','b22h2')
	builds.winOSBoolSelected["585D"]=Win11_22h2

	sh.printStringLiteral=conr.getboolean('MISC','print_string_literal_of_bytes')
	sh.show_comments=conr.getboolean('MISC','show_comments')

	sh.style=conr.get('MISC', 'syscall_style')
	sh.intendedCompiler=conr.get('MISC', 'intended_compiler')
	sh.useSharedData=conr.getboolean('MISC','use_shareddata_for_win1011')
	
	sh.encodeUSD=conr.getboolean('MISC','encode_user_share_data')
	sh.addUSD=conr.getboolean('MISC','usd_encode_with_add')

	sh.user12Teb=conr.getboolean('MISC','get_teb_from_r12') 

	temp=conr.get('MISC', 'usd_encode_xor_key')
	temp2=conr.get('MISC', 'usd_encode_add_val')

	try:
		sh.encodeUSDKey=int(temp)
	except:
		sh.encodeUSDKey=int(temp,16)

	try:
		sh.addUSDVal=int(temp2)
	except:
		sh.addUSDVal=int(temp2,16)

	# print (red+str(sh.show_comments)+res, "sh.show_comments")
	if r22h2:
		sh.osChoices2.append("4A65")
	if r21h2:
		sh.osChoices2.append("4A64")
	if r21h1:
		sh.osChoices2.append("21h1")
	if r20h2:
		sh.osChoices2.append("20h2")
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
	if Win11_21h2:
		sh.osChoices2.append("55F0")
	if Win11_22h2:
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

	show_commentsVal=sh.show_comments
	syscallStyleVal=sh.style
	intendedCompilerVal=sh.intendedCompiler
	useSharedDataVal=sh.useSharedData
	
	boolEncodeUSD=sh.encodeUSD
	encodeXorKeyVal=hex(sh.encodeUSDKey)
	boolEncodeWAdd=sh.addUSD
	encodeAddValsh=hex(sh.addUSDVal)

	checkWinOSBools()
	r21h2 = builds.winOSBoolSelected["4A64"]
	r22h2 = builds.winOSBoolSelected["4A65"]
	r21h1 = builds.winOSBoolSelected["21h1"]
	r20h2 = builds.winOSBoolSelected["20h2"]
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
	b21h2 = builds.winOSBoolSelected["55F0"]
	b22h2 = builds.winOSBoolSelected["585D"]

	

	listofStrings=["r21h2",	"r22h2", "r21h1",	"r20h2",	"r2004",	"r1909",	"r1903",	"r1809",	"r1803",	"r1709",	"r1703",	"r1607",	"r1511","r1507","sp0","sp1", "b21h2", "b22h2","show_comments","syscall_style", "intended_compiler","use_shareddata_for_win1011","encode_user_share_data","usd_encode_xor_key", "usd_encode_with_add","usd_encode_add_val","get_teb_from_r12"]
	
	listofBools=[r21h2,r22h2, r21h1, r20h2, r2004, r1909, r1903, r1809, r1803, r1709, r1703, r1607, r1511, r1507,sp0,sp1,b21h2, b22h2, show_commentsVal,syscallStyleVal,intendedCompilerVal,useSharedDataVal,boolEncodeUSD,encodeXorKeyVal,boolEncodeWAdd,encodeAddValsh,sh.user12Teb] 

	listofStrings.append("selected_syscalls")
	listofBools.append(sh.list_of_syscalls)
	# print (listofStrings)
	# print(listofBools)

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
	
	# Win11_21h2=conr.getboolean('Windows 11','r21h2')
	# builds.winOSBoolSelected["55F0"]=Win11_21h2

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
		# print (configOptions)
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

def buildSyscall(print_to_file=False):
	# osChoices = ["4A62","3AD7", "47BA","1DB0", "55F0", "4A64"]

	# syscallChoices=["NtAllocateVirtualMemory", "NtCreateKey", "NtReplaceKey","NtSetContextThread", "NtSetValueKey"]
	com1=com2=com3=com4=com5=com6=com64=com9=comGetPC=com11=com10="\n"
	com8=com12=com13=com14=ws=xwin7L1=xwin7L2=xwin7L3=xwin7L4=xwin7L5=xwin7L6=xwin7L7=xwin7L7=comx64Ext1=comx64Ext2=comx64Ext3=comx64Ext4=comx64Ext5=comx64Ext6=comx64Ext7=comx64Ext8=comx64Ext9=comx64Ext10=comx64Ext11=comx64Ext12=comx64Ext13=comx64Ext14=comx64Ext15=comx64Ext16=comx64Ext17=comUSD=comUSDxor= com15=com16=  com17=com18= com19=com20=com21=comhg=comhg86=comhg64=""

	if sh.show_comments:
		com1="\t\t; "+mag+"Syscall Function"+res+"\n"
		com2="\t\t\t; "+gre+"Windows 10/11 Syscall"+res+"\n"
		com3="\t\t\t; "+gre+"Windows 7 Syscall"+res+"\n"
		com4="\t\t; "+yel+"Push 0x33 selector for 64-bit"+res+"\n"
		com5="\t\t; "+yel+"Create return address for leaving kernel-mode"+res+"\n"
		com6="\t\t; "+yel+"Create destination for Heaven's gate"+res+"\n"
		com64="\t\t\t; "+mag+"Invoke Heaven's gate"+yel+"--transition to x64 code"+res+"\n"
		com86="\t\t\t; "+mag+"Invoke Heaven's gate"+yel+"--transition to x86 code"+res+"\n"
		comhg="\t\t\t; "+mag+"Invoke Heaven's gate"+res
		comhg86="\t\t\t; "+mag+"Invoke Heaven's gate"+yel+" -- go x86"+res
		comhg64="\t\t\t; "+mag+"Invoke Heaven's gate"+yel+" -- go x64"+res
		


		com8="\t; "+yel+"x64 code as bytes, leading to "+mag+"syscall"+res+""
		com10="\n\t\t\t; "+yel+"x64 code: "+cya+"jmp qword ptr [r15+0F8h]"+res+"\n"
		com12="\t; "+yel+"Formatted for "+blu+"VisualStudio inline Assembly"+res
		com13="\t; "+cya+"jmp qword ptr [r15+0F8h]"+res+""
		com14="\t; "+yel+"x64 code will enter kernel-mode and then return"+res+""
		com15=res+"\t # "+yel+"Save 32-bit registers"+res
		com16=res+"\t # "+yel+"into WOW64_CONTEXT"+res
		com17=res+"\t # "+yel+"Save x86 EIP"+res
		com18=res+"\t # "+yel+"Save x86 ESP"+res
		com19=res+"\t # "+yel+"Save x86 EFlags"+res
		com20=res+"\t # "+yel+"Pointer to syscall args"+res
		com21=res+"\t # "+yel+"Get TurboThunk, if needed"+res






		com9="\t; "+yel+"Return from kernel-mode, back to 32-bit"+res+"\n"
		comGetPC="\t\t; "+yel+"GetPC"+res+"\n"
		ws=res+"; "+cya
		com11="\n\t\t\t; "+cya+"""mov r8d,dword ptr [esp] 
			{}mov dword ptr [r13+0BCh],r8d
			{}add esp,0x4
			{}mov dword ptr [r13+0C8h],esp
			{}mov rsp,qword ptr [r12+1480h]
			{}and qword ptr [r12+1480h],0
			{}mov r11d,edx
			{}jmp qword ptr [r15+rcx*8]{}

			""".format(ws,ws,ws,ws,ws,ws,ws,res)
		com11Ex="\n\t\t\t; "+cya+"""xchg rsp,r14
			{}mov r8d,dword ptr [r14]
			{}add r14,4
			{}mov dword ptr [r13+3Ch],r8d{}
			{}mov dword ptr [r13+48h],r14d{}
			{}sub r14,4
			{}lea r11,[r14+4]            {}
			{}mov dword ptr [r13+20h],edi{}
			{}mov dword ptr [r13+24h],esi{}
			{}mov dword ptr [r13+28h],ebx
			{}mov dword ptr [r13+38h],ebp
			{}pushfq                     
			{}pop r8                     {}
			{}mov dword ptr [r13+44h],r8d
			{}mov ecx,eax
			{}shr ecx,10h                {}
			{}jmp qword ptr [r15+rcx*8]{}
			""".format(ws,ws,ws,com17, ws,com18,ws,ws,com20,ws,com15,ws, com16,ws,ws,ws,ws,com19,ws,ws,ws,com21,ws,res,ws,ws,ws,ws)



		comUSD="\t; " +cya+"User_Shared_Data:"+yel+" OSBuild "+res
		comUSDxor= "\t\t; " +gre+"XOR result = 0x7ffe0260,"+res
		xwin7L1="; "+cya+"mov r8d,dword ptr [esp]"+res
		xwin7L2="; "+cya+"mov dword ptr [r13+0BCh],r8df"+res
		xwin7L3="; "+cya+"add esp,0x4"+res
		xwin7L4="; "+cya+"mov dword ptr [r13+0C8h],esp"+res
		xwin7L5="; "+cya+"mov rsp,qword ptr [r12+1480h]"+res
		xwin7L6="; "+cya+"and qword ptr [r12+1480h],0"+res
		xwin7L7="; "+cya+"mov r11d,edx"+res
		xwin7L8="; "+cya+"jmp qword ptr [r15+rcx*8]"+res


		# com16=res+"\t # "+yel+"into WOW64_CONTEXT"+res
		# com17=res+"\t # "+yel+"Save x86 EIP"+res
		# com18=res+"\t # "+yel+"Save x86 ESP"+res
		# com19=res+"\t # "+yel+"Save x86 EFlags"+res
		# com20=res+"\t # "+yel+"Pointer to syscall args"+res
		# com21=res+"\t # "+yel+"Get TurboThunk, if needed"+res

		comx64Ext1="; "+cya+"xchg rsp,r14"+res
		comx64Ext2="; "+cya+"mov r8d,dword ptr [r14]"+res
		comx64Ext3="; "+cya+"add r14,4"+res
		comx64Ext4="; "+cya+"mov dword ptr [r13+3Ch],r8d {}".format(com17)+res
		comx64Ext5="; "+cya+"mov dword ptr [r13+48h],r14d {}".format(com18)+res
		comx64Ext6="; "+cya+"sub r14,4"+res
		comx64Ext7="; "+cya+"lea r11,[r14+4] {}".format("\t"+com20)+res
		comx64Ext8="; "+cya+"mov dword ptr [r13+20h],edi {}".format(com15)+res
		comx64Ext9="; "+cya+"mov dword ptr [r13+24h],esi {}".format(com16)+res
		comx64Ext10="; "+cya+"mov dword ptr [r13+28h],ebx"+res
		comx64Ext11="; "+cya+"mov dword ptr [r13+38h],ebp"+res
		comx64Ext12="; "+cya+"pushfq"+res
		comx64Ext13="; "+cya+"pop r8 {}".format("\t\t"+com19)+res
		comx64Ext14="; "+cya+"mov dword ptr [r13+44h],r8d"+res
		comx64Ext15="; "+cya+"mov ecx,eax"+res
		comx64Ext16="; "+cya+"shr ecx,10h {}".format("\t\t"+com21)+res
		comx64Ext17="; "+cya+"jmp qword ptr [r15+rcx*8]"+res
		
		comr12="\t\t; "+gre+"x64: "+cya+"mov ebx,dword ptr [r12]"+res
		comr12TEB="\t\t; "+yel+"Get TEB from TEB64"+res


	getPebr12_inline="""_emit 0x41 {}
_emit 0x8b {}
_emit 0x1c
_emit 0x24

""".format(comr12,comr12TEB)

	getPebr12_nasm="""db 0x41,0x8b,0x1c,0x24{}	
		{}
""".format(comr12[1:],"",comr12TEB)

	if sh.comp()=="nasm":
		getPebr12=getPebr12_nasm
	elif sh.comp()=="inlineVS":
		getPebr12=getPebr12_inline

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
	# 21h2 build 22000 55F0

	# print (syscallChoices)
	# print ("revSyscallChoices", revSyscallChoices)
	endInitializer="""
saveSyscallArray:
push eax
mov edi, esp
add edi, 0x4
mov esp, ecx

"""
	if isWin7() and isWin1011() and not sh.user12Teb:
		initializerStart="""
mov eax, fs:[0x30]
mov ebx, [eax+0xac]
mov eax, [eax+0xa4]
mov ecx, esp
sub esp, 0x1000

"""
	elif isWin7() and isWin1011() and sh.user12Teb:
		initializerStart="""push 0x33
call GetPC1
GetPC1:
add [esp], 5 
retf{}

""".format(comhg64)
		initializerStart+=getPebr12
		initializerStart+="""push 0x23
call GetPC2
GetPC2:
mov [esp+4], 0x23
add [esp], 0xa
retf{}
    
mov eax, [ebx+0x30]
mov ebx, [eax+0xac]
mov eax, [eax+0xa4]
mov ecx, esp
sub esp, 0x1000

""".format(comhg86)

	else:
		if (isWin7() and not sh.user12Teb) or (isWin1011() and not sh.useSharedData and not sh.user12Teb):
			initializerStart="""mov ebx, fs:[0x30]
mov ebx, [ebx+0xac]
mov ecx, esp
sub esp, 0x1000

""" 
		elif (isWin7() or (isWin1011()) and sh.user12Teb):

			initializerStart="""push 0x33
call GetPC1
GetPC1:
add [esp], 5 
retf{}

""".format(comhg64)
			initializerStart+=getPebr12
			initializerStart+="""push 0x23
call GetPC2
GetPC2:
mov [esp+4], 0x23
add [esp], 0xa
retf {}

mov ebx, [ebx+0x30]
mov ebx, [ebx+0xac]
mov ecx, esp
sub esp, 0x1000

""".format(comhg86)
		else:
			initializerStart="""mov ebx,0x7ffe0260  {}
mov ebx, [ebx]
mov ecx, esp
sub esp, 0x1000

""".format(comUSD)
			if sh.encodeUSD and not sh.addUSD:
				initializerStart="""mov ebx,{}  
mov edx, {} 
xor ebx, edx {}
mov ebx, [ebx] {}
mov ecx, esp
sub esp, 0x1000

""".format(hex(0x7ffe0260 ^sh.encodeUSDKey), hex(sh.encodeUSDKey),  comUSDxor,"\t" +comUSD)

			if sh.encodeUSD and sh.addUSD:
				initializerStart="""mov ebx,{}  
mov edx, {} 
add ebx, {}
xor ebx, edx {}
mov ebx, [ebx] {}
mov ecx, esp
sub esp, 0x1000

""".format(hex((0x7ffe0260 ^sh.encodeUSDKey)-sh.addUSDVal), hex(sh.encodeUSDKey),hex(sh.addUSDVal),  comUSDxor,"\t" +comUSD)
			if not sh.encodeUSD and sh.addUSD:
				initializerStart="""mov ebx,{}  
add ebx, {}
mov ebx, [ebx] {}
mov ecx, esp
sub esp, 0x1000

""".format(hex(0x7ffe0260 -sh.addUSDVal),hex(sh.addUSDVal), "\t" +comUSD)


		endInitializer="""
saveSyscallArray:
mov edi, esp
mov esp, ecx

"""	
	checkOsRelease=generateInitializer=generateSyscallParams=""
	saveSyscallArray="""push edi

	"""
	
	basicWin7to11Syscall="\nourSyscall:"+com1
	basicWin7to11Syscall+="""cmp dword ptr [edi-0x4],0xa
jne win7

"""

	basicWin7to11Syscall+="\nwin10:"+com2
	basicWin7to11Syscall+="""call dword ptr fs:[0xc0]
ret 
"""
	basicWin7to11Syscall+="\nwin7:"+com3
	basicWin7to11Syscall+="""xor ecx, ecx
lea edx, [esp+4]
call dword ptr fs:[0xc0]
add esp, 4
ret"""
	ourSyscallx64Win71011Prologue="\nourSyscall:"+com1
	ourSyscallx64Win71011Prologue+="""cmp dword ptr [edi-0x4],0xa
jne win7

"""
	ourSyscallx64Win71011Prologue+="win10:" +com2
	

	ourSyscallx64Win1011Basic="""call buildDestRet
buildDestRet:
add [esp], 0x17"""+com5

	ourSyscallx64Win1011="push 0x33"+com4
	ourSyscallx64Win1011+="call nextRetf"+comGetPC
	ourSyscallx64Win1011+="""nextRetf:
add [esp], 5"""+com6
	ourSyscallx64Win1011+="retf"+com64

	# ourSyscallx64Win71011Prologue="win10:" +com2
	ourSyscallx64Win1011Ex="push 0x33"+com4
	ourSyscallx64Win1011Ex+="call nextRetf"+comGetPC
	ourSyscallx64Win1011Ex+="""nextRetf:
add [esp], 5"""+com6
	ourSyscallx64Win1011Ex+="retf"+com64

	x64Win10="db 0x41,0xff,0xa7,0xf8,0x00,0x00,0x00 "+com8+com10
	# sh.setComp("inlineVS")
	x64Win10Inline="""
_emit 0x41 	{}
_emit 0xff 	{}
_emit 0xa7 	{}
_emit 0xf8
_emit 0x00 	{}
_emit 0x00
_emit 0x00  

""".format(com8,"",com12,com13)

	x64Win10Ex="db 0x49,0x87,0xe6,0x45,0x8b,0x06,0x49,0x83,0xc6,0x04,0x45,0x89,0x45,0x3c,0x45,0x89,0x75,0x48,0x49,\n0x83,0xee,0x04,0x4d,0x8d,0x5e,0x04,0x41,0x89,0x7d,0x20,0x41,0x89,0x75,0x24,0x41,0x89,0x5d,0x28,0x41,\n0x89,0x6d,0x38,0x9c,0x41,0x58,0x45,0x89,0x45,0x44,0x89,0xc1,0xc1,0xe9,0x10,0x41,0xff,0x24,0xcf"+"\n\t\t"+com8+com11Ex

	x64Win10ExInline="""
_emit 0x49	{}
_emit 0x87	{}
_emit 0xe6 		{}  
_emit 0x45 		{}  
_emit 0x8b 		{}  
_emit 0x06 		{}  
_emit 0x49 		{}  
_emit 0x83 		{}  
_emit 0xc6 		{}  
_emit 0x04 		{}  
_emit 0x45 		{}  
_emit 0x89 		{}  
_emit 0x45 		{}  
_emit 0x3c 		{}  
_emit 0x45 		{}  
_emit 0x89 		{}
_emit 0x75 		{}
_emit 0x48 		{}
_emit 0x49		{}
_emit 0x83
_emit 0xee
_emit 0x04
_emit 0x4d
_emit 0x8d
_emit 0x5e
_emit 0x04
_emit 0x41
_emit 0x89
_emit 0x7d
_emit 0x20
_emit 0x41
_emit 0x89
_emit 0x75
_emit 0x24
_emit 0x41
_emit 0x89
_emit 0x5d
_emit 0x28
_emit 0x41
_emit 0x89
_emit 0x6d
_emit 0x38
_emit 0x9c
_emit 0x41
_emit 0x58
_emit 0x45
_emit 0x89
_emit 0x45
_emit 0x44
_emit 0x89
_emit 0xc1
_emit 0xc1
_emit 0xe9
_emit 0x10
_emit 0x41
_emit 0xff
_emit 0x24
_emit 0xcf   
""".format(com8,"",comx64Ext1,comx64Ext2,comx64Ext3,comx64Ext4,comx64Ext5,comx64Ext6,comx64Ext7,comx64Ext8,comx64Ext9,comx64Ext10,comx64Ext11,comx64Ext12,comx64Ext13,comx64Ext14,comx64Ext15,comx64Ext16,comx64Ext17)

	if sh.comp()=="nasm":
		ourSyscallx64Win1011+=x64Win10
	elif sh.comp()=="inlineVS":
		ourSyscallx64Win1011+=x64Win10Inline

	if sh.comp()=="nasm":
		ourSyscallx64Win1011Ex +=x64Win10Ex
	elif sh.comp()=="inlineVS":
		ourSyscallx64Win1011Ex +=x64Win10ExInline


	ourSyscallx64Epilogue="ret 		"+com9
	ourSyscallx64Win1011+=ourSyscallx64Epilogue
	

	ourSyscallx64Win7Prologue= "\nwin7:"+com3
	ourSyscallx64Win7= """xor ecx, ecx
lea edx, [esp+4]
push 0x33"""+com4
	ourSyscallx64Win7+= "call nextRetf2"+comGetPC
	ourSyscallx64Win7+="""nextRetf2:
add [esp], 5"""+com6
	ourSyscallx64Win7+= "retf"+com64
	x64Win7= "db 0x67,0x44,0x8b,0x04,0x24,0x45,0x89,0x85,0xbc,0x00,0x00,0x00,0x83,0xc4,0x04,0x41,0x89,0xa5,\n0xc8,0x00,0x00,0x00,0x49,0x8b,0xa4,0x24,0x80,0x14,0x00,0x00,0x49,0x83,0xa4,0x24,0x80,0x14,0x00,\n0x00,0x00,0x44,0x8b,0xda,0x41,0xff,0x24,0xcf"+"\t"+com8+com11
	x64Win7Inline=	"""
_emit 0x67	{}
_emit 0x44	{}
_emit 0x8B 	{}
_emit 0x04
_emit 0x24		{}
_emit 0x45		{}
_emit 0x89		{}
_emit 0x85		{}
_emit 0xBC		{}
_emit 0x00		{}
_emit 0x00		{}
_emit 0x00		{}
_emit 0x83
_emit 0xc4
_emit 0x04
_emit 0x41
_emit 0x89
_emit 0xA5
_emit 0xC8
_emit 0x00
_emit 0x00
_emit 0x00
_emit 0x49
_emit 0x8B
_emit 0xA4
_emit 0x24
_emit 0x80
_emit 0x14
_emit 0x00
_emit 0x00
_emit 0x49
_emit 0x83
_emit 0xA4
_emit 0x24
_emit 0x80
_emit 0x14
_emit 0x00
_emit 0x00
_emit 0x00
_emit 0x44
_emit 0x8B
_emit 0xDA
_emit 0x41
_emit 0xFF
_emit 0x24
_emit 0xCF""".format(com8,"",com12,xwin7L1,xwin7L2,xwin7L3,xwin7L4,xwin7L5,xwin7L6,xwin7L7, xwin7L8)
	# sh.setComp("inlineVS")
	if sh.comp()=="nasm":
		ourSyscallx64Win7+=x64Win7
	elif sh.comp()=="inlineVS":
		ourSyscallx64Win7+=x64Win7Inline


	ourSyscall=""
	if isWin7() and  isWin1011():
		if sh.style=="fs":
			ourSyscall=basicWin7to11Syscall+"\n"
		elif sh.style=="x64":
			ourSyscall =ourSyscallx64Win71011Prologue + ourSyscallx64Win1011Basic + ourSyscallx64Win1011 +ourSyscallx64Win7Prologue + ourSyscallx64Win7
		elif sh.style=="x64Ex":
			ourSyscall =ourSyscallx64Win71011Prologue + ourSyscallx64Win1011Ex +ourSyscallx64Win7Prologue + ourSyscallx64Win7
	elif isWin1011():
		ourSyscallPrologue="\nourSyscall:"+com1
		ourSyscallBasicWin1011="""call dword ptr fs:[0xc0]
ret"""

		if sh.style=="fs":
			ourSyscall=ourSyscallPrologue +  ourSyscallBasicWin1011+"\n"
		elif sh.style=="x64":
			ourSyscall = ourSyscallPrologue + ourSyscallx64Win1011Basic+ ourSyscallx64Win1011
		elif sh.style=="x64Ex":
			ourSyscall = ourSyscallPrologue +  ourSyscallx64Win1011Ex


	elif isWin7():
		ourSyscallPrologue="\nourSyscall:"+com1
		ourSyscallBasicWin7="""xor ecx, ecx
lea edx, [esp+4]
call dword ptr fs:[0xc0]
add esp, 4
ret"""	
		if sh.style=="fs":
			ourSyscall=ourSyscallPrologue +  ourSyscallBasicWin7+"\n"
		elif sh.style=="x64":
			ourSyscall = ourSyscallPrologue +  ourSyscallx64Win7
		elif sh.style=="x64Ex":
			ourSyscall = ourSyscallPrologue +  ourSyscallx64Win7
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
		
		ediRestoral=0
		if sh.style=="fs":
			ediRestoral=hex(numSyscallParams*4)
		else:
			# ediRestoral=hex(4+numSyscallParams*4)
			ediRestoral=hex(numSyscallParams*4)

		stackCleanupRestore="mov edi, [esp+" + ediRestoral +"]\n\n"
		# stackCleanupRestore="add esp, " + hex(numSyscallParams*4) + "\n"  // DEPRECATED
		# stackCleanupRestore+="pop edi\n\n"  // DEPRECATED
		#### mov edi, [esp+0x] provides greater stability for a shellcode with a longer sequence of syscalls. 
		generateSyscallParams +=stackCleanupRestore

	# print (win10ReverseLookup["15063"])

	# print (hex(sysCallName))

	
	finalSyscallShellcode= initializerStart+generateInitializer+endInitializer+generateSyscallParams+ endShellcode0+ ourSyscall + endShellcode1
	
	out= finalSyscallShellcode
	
	
	finalSyscallShellcode = finalSyscallShellcode.replace(gre,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(res,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(mag,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(yel,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(blu,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(res,'')
	finalSyscallShellcode = finalSyscallShellcode.replace(cya,'')
	finalSyscallShellcodeText=finalSyscallShellcode
	# finalSyscallShellcode = finalSyscallShellcode.replace(';','#')
	out2= finalSyscallShellcode

	# print (finalSyscallShellcodeText)

	#generate bytes
	# generateBytes(finalSyscallShellcode)
	

	if print_to_file:
		time = datetime.datetime.now()
		filetime = time.strftime("%Y%m%d_%H%M%S")
		
		win="Win"
		if isWin7():
			win+="7"
		if isWin1011():
			win+="1011"
		
		t=0
		sys=""
		for each in sh.list_of_syscalls:
			if t<3:
				sys+=each+"_"
			t+=1

		outputFileName=win+"_"+sys+filetime+".txt"
		
		output_dir = os.getcwd()

		myOutDir = "current_dir" #todo
		if myOutDir == "current_dir":
			output_dir = os.path.join(os.path.dirname(__file__), "Syscall Output")
		else:
			output_dir = myOutDir #todo

		txtFileName =  os.path.join(output_dir, outputFileName)
		os.makedirs(os.path.dirname(txtFileName), exist_ok=True)
		text = open(txtFileName, "w")
		text.write (out2)
		# text.write(emulation_txt)
		text.close()

		print(red+" Saved file to: "+res, txtFileName)
		
	# if sh.printStringLiteral:
	# 	print(sRaw.bytesShellcode)

	# 	print(sRaw.shellCodeStrLit)

	return out

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

def selectFindOSBuildText():
	if sh.encodeUSD:
		togE=res+"["+gre+"X"+res+"]"
	else:
		togE=res+"["+gre+" "+res+"]"
	if sh.addUSD:
		togA=res+"["+gre+"X"+res+"]"
	else:
		togA=res+"["+gre+" "+res+"]"

	togK=res+"["+gre+hex(sh.encodeUSDKey)+res+"]"
	togAV=res+"["+gre+hex(sh.addUSDVal)+res+"]"

	togP=res+"["+gre+" "+res+"]"
	if sh.useSharedData:
		togSD=res+"["+gre+"X"+res+"]"
	else:
		togSD=res+"["+gre+" "+res+"]"

	if sh.user12Teb:
		togR=res+"["+gre+"X"+res+"]"
		togP=res+"["+gre+" "+res+"]"
	else:
		togR=res+"["+gre+" "+res+"]"
		togP=res+"["+gre+"X"+res+"]"


	text="  ShellWasp offers different ways to identify the OSBuild in WoW64 shellcode.\n    If more than one is selected, it will try {} first and then {}. \n    {} is default or used if others are not supported by OS.\n\n".format(gre+"r12_PEB"+res, gre+"User_Shared_Data"+res,gre+"fs_PEB"+res)





	text+=yel+"   {}\t {}  {} {} Uses {} to find PEB and identify OS Build\n".format(cya+"1"+res,mag+"fs_PEB" +res, togP, "-"+yel, cya+"fs:[0x30]"+yel)
	text+=red+"\t\t\tSupported:"+res+" Windows 7-11\n"
	
	text+=yel+"   {}\t {} {} {} Uses {} and {} to find PEB and identify OS Build\n".format(cya+"2"+res,mag+"r12_PEB" +res, togR, "-"+yel, cya+"Heaven's Gate"+yel, cya+"r12"+yel)

	text+="\t\t\t "+res+"x64 code, "+cya+"mov ebx,dword ptr [r12]"+res+ ", gets"+cya+" TEB"+res+" from "+cya+"TEB64"+res+".\n"+res
	text+=red+"\t\t\tSupported:"+res+" Windows 7-11\n"

	text+=yel+"   {}\t {}     {} {} Uses {} to identify OS Build\n".format(cya+"3"+res,mag+"usd" +res, togSD, "-"+yel, cya+"User_Shared_Data"+yel, cya+"r12"+yel)
	text+=red+"\t\t\tSupported:"+res+" Windows 10-11\n"
	
	# text+="\t\t\t "+res+"Supported only on Win10/11.\n\n"
	text+=yel+"   {}\t {}  {} {} Encode {} to determine OS build with XOR key {}.{}\n".format(cya+"4"+res,mag+"encode" +res,  togE,"-"+yel,cya+ "User_Shared_Data"+yel,cya+hex(sh.encodeUSDKey),res)
	text+=yel+"   {}\t {}     {} {} Change XOR key for encoding {}.\n".format(cya+"5"+res,mag+"xor" +res,togK,"-"+yel,cya+"User_Shared_Data"+res)
	text+=yel+"   {}\t {}     {} {} Get {} by adding {} to starting value, {}.{}\n".format(cya+"6"+res,mag+"add" +res,  togA,"-"+yel,cya+ "User_Shared_Data"+yel,gre+hex(sh.addUSDVal)+yel,cya+hex(0x7ffe0260 -sh.addUSDVal) +yel,res)
	text+=yel+"   {}\t {} {} {} Change value to add to get {}.{}\n\n".format(cya+"7"+res,mag+"add_val" +res,  togAV,"-"+yel,cya+ "User_Shared_Data"+yel,res)


	text+=gre+"   {} {} Show this submenu\n".format(cya+"h"+gre, res+"-"+gre)
	text+=gre+"   {} {} Exit\n".format(cya+"x"+gre,res+"-"+gre)

	return text
def selectFindOSBuild():
	text=selectFindOSBuildText()
	print (text)
	userIN=""
	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ShellWasp>"+ cya+"Style>" + mag + "OSBuild>" +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:2] == "fs":
				sh.user12Teb=False
				sh.useSharedData=False
				print ("  "+mag+"fs_PEB "+res+"is always on by default, but it can be overridden by other choices."+res)
				print ("  "+mag+"r12_PEB"+res+" changed to: ", gre+str(sh.user12Teb)+res)
				print ("  "+mag+"User_Shared_Data"+res+" changed to: ", gre+str(sh.useSharedData)+res)
				print ("\n  Type {} or {} to exit".format(red+"x"+res, red+"q"+res))


			elif userIN[0:1] == "2" or userIN[0:2].lower() == "fs".lower():
				sh.user12Teb=True
				sh.useSharedData=False
				print ("  "+mag+"r12_PEB"+res+" changed to: ", gre+str(sh.user12Teb)+res)
				print ("  "+mag+"User_Shared_Data"+res+" changed to: ", gre+str(sh.useSharedData)+res)
				print ("\n  Type {} or {} to exit".format(red+"x"+res, red+"q"+res))

			elif userIN[0:1] == "3" or userIN[0:3] == "r12":
				sh.user12Teb=False
				sh.useSharedData=True
				print ("  "+mag+"r12_PEB"+res+" changed to: ", gre+str(sh.user12Teb)+res)
				print ("  "+mag+"User_Shared_Data"+res+" changed to: ", gre+str(sh.useSharedData)+res)
				print ("\n  Type {} or {} to exit".format(red+"x"+res, red+"q"+res))










			elif userIN[0:1] == "4" or userIN[0:6].lower() == "encode".lower():
				if not sh.encodeUSD:
					sh.encodeUSD=True
				else:
					sh.encodeUSD=False
				print ("  Encode User_Shared_Data: ", mag+str(sh.encodeUSD)+res)
			elif userIN[0:1] == "5" or userIN[0:3].lower() == "xor".lower():
				hexInput=input("  Enter hexadecimal XOR key: ")
				try: 
					sh.encodeUSDKey=int(hexInput,16)
				except:
					try:
						sh.encodeUSDKey=int("0x"+hexInput,16)
					except:
						print (red+"   Unacceptable input."+res)
				print ("  XOR key: " + mag+hex(sh.encodeUSDKey)+res)
			elif userIN[0:1] == "6" or userIN[0:3].lower() == "add".lower():
				if not sh.addUSD:
					sh.addUSD=True
				else:
					sh.addUSD=False
				print ("  Add User_Shared_Data: ", mag+str(sh.encodeUSD)+res)				
			elif userIN[0:1] == "7" or userIN[0:7].lower() == "add_val".lower():
				print("   ShellWasp gets the {} by adding two values to get {}.".format(cya+"User_Shared_Data"+res, cya+"0x7ffe0260"+res))
				print("   Supply the value to be added; ShellWasp will calcuate the starting point.\n".format(cya+"User_Shared_Data"+res))

				hexInput=input("  Enter hexadecimal add value: ")
				temp=0
				try: 
					temp=int(hexInput,16)
					if len(hex(temp))>10:
						print ("  Input is too large.")
					elif temp>0x7ffe0260:
						print ("  Select a value less than "+cya+"0x7ffe0260."+res)
						continue
					else:
						sh.addUSDVal=temp
				except:
					try:
						temp=int("0x"+hexInput,16)
						if len(hex(temp))>10:
							print ("  Input is too large.")
						elif temp>0x7ffe0260:
							print ("  Select a value less than "+cya+"0x7ffe0260."+res)
							continue
						else:
							sh.addUSDVal=temp
					except:
						print (red+"   Unacceptable input."+res,temp )
				text="   ShellWasp will add {} to {} to get {}\n".format(mag + hex(sh.addUSDVal)+res, mag + hex(0x7ffe0260-sh.addUSDVal)+res, cya+"User_Shared_Data"+res )
				print(text)



			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			elif userIN[0:1] == "h":
				print(selectFindOSBuildText())
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style submenu.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")


def selectSyscallStyle():
	if sh.style=="x64":
		togX64=res+"["+gre+"X"+res+"]"
		togFs=res+"["+gre+" "+res+"]"
		togX=res+"["+gre+" "+res+"]"
	elif sh.style=="fs":
		togFs=res+"["+gre+"X"+res+"]"
		togX64=res+"["+gre+" "+res+"]"
		togX=res+"["+gre+" "+res+"]"
	elif sh.style=="x64Ex":
		togFs=res+"["+gre+" "+res+"]"
		togX64=res+"["+gre+" "+res+"]"
		togX=res+"["+gre+"X"+res+"]"

	text="   ShellWasp offers different ways to invoke the syscall for 32-bit, WoW64 shellcode:\n"
	text+=yel+"   {}\t {}    {} {} Uses {} to invoke syscall\n".format(cya+"1"+res,mag+"fs" +res, togFs, "-"+yel, cya+"fs:[0xc0]"+yel)
	text+=yel+"   {}\t {}   {} {} Uses Heaven's gate and executes {} to invoke syscall\n".format(cya+"2"+res,mag+"x64" +res,  togX64,"-"+yel, cya+"x64 code"+yel)
	text+=yel+"   {}\t {} {} {} Uses Heaven's gate and executes {} to invoke syscall\n".format(cya+"3"+res,mag+"x64Ex" +res,  togX,"-"+yel, cya+"extended x64 code"+yel)
	text+=yel+"   \t\t     Win10/11 only\n".format(cya+""+res)


	# text+=gre+"\n   Note:"+res+" The way in which the syscall is invoked differs based on OS. ShellWasp manages this\n\tbased on your selections of targeted OS builds.\n "

	print (text)
	userIN=""
	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ShellWasp>"+ cya+"Style>" + mag + "Syscall>" +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:2] == "fs":
				sh.style="fs"
				print ("  Style changed to: ", mag+sh.style+res)
				print ("  This method is most similar to what the OS does naturally with syscalls in WoW64."+res)

				break
			elif userIN[0:1] == "3" or userIN[0:5].lower() == "x64Ex".lower():
				sh.style="x64Ex"
				print ("  Style changed to: ", mag+sh.style+res)
				print ("  This method uses {} to preserve and restore stack and CPU context (registers).".format(cya+"WOW64_CONTEXT"+res))
				break				
			elif userIN[0:1] == "2" or userIN[0:3] == "x64":
				sh.style="x64"
				print ("  Style changed to: ", mag+sh.style+res)
				print ("  This method uses {} to preserve and restore stack and CPU context (registers).".format(cya+"WOW64_CONTEXT"+res))
				break
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style submenu.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")

def selectCompilerStyle():
	if sh.intendedCompiler=="nasm":
		togN=res+"["+gre+"X"+res+"]"
		togV=res+"["+gre+" "+res+"]"
	elif sh.intendedCompiler=="inlineVS":
		togV=res+"["+gre+"X"+res+"]"
		togN=res+"["+gre+" "+res+"]"

	text="   When invoking the syscall via Heaven's gate and executing x64 code, there are different options\n   on how to represent x64 code. Different formats are required based on compiler:\n"
	
	text+=yel+"   {}\t {}  {} {} Uses x64 bytes in the style of {} for compilers like {}\n".format(cya+"1"+res,mag+"nasm" +res, togN, "-"+yel,cya+"db 0xde,0xad,0xbe,0xef"+yel, cya+"NASM"+res)
	
	text+=yel+"   {}\t {} {} {} Prepares x64 bytes for {} using the emit keyword:{}\n".format(cya+"2"+res,mag+"inlineVS" +res,  togV,"-"+yel,cya+ "VisualStudio inline Assembly"+yel, cya+"\n\t\t_emit 0xde\n\t\t_emit 0xad\n\t\t_emit 0xbe\n\t\t_emit 0xef\n"+res)

	print (text)
	userIN=""
	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ShellWasp>"+ cya+"Style>" + mag + "Format>" +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:4] == "nasm":
				sh.intendedCompiler ="nasm"
				print ("  Style changed to: ", mag+sh.intendedCompiler+res)
				break
			if userIN[0:1] == "2" or userIN[0:8].lower() == "inlineVS".lower():
				sh.intendedCompiler ="inlineVS"
				print ("  Style changed to: ", mag+sh.intendedCompiler+res)
				break
			if userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")

def selectUserSharedOptions():
	if sh.useSharedData:
		togU=res+"["+gre+"X"+res+"]"
		togF=res+"["+gre+" "+res+"]"
	else:
		togF=res+"["+gre+"X"+res+"]"
		togU=res+"["+gre+" "+res+"]"
	if sh.encodeUSD:
		togE=res+"["+gre+"X"+res+"]"
	else:
		togE=res+"["+gre+" "+res+"]"
	if sh.addUSD:
		togA=res+"["+gre+"X"+res+"]"
	else:
		togA=res+"["+gre+" "+res+"]"

	togK=res+"["+gre+hex(sh.encodeUSDKey)+res+"]"
	togAV=res+"["+gre+hex(sh.addUSDVal)+res+"]"

	togP=res+"["+gre+" "+res+"]"
	if sh.useSharedData:
		togSD=res+"["+gre+"X"+res+"]"
	else:
		togSD=res+"["+gre+" "+res+"]"

	if sh.user12Teb:
		togR=res+"["+gre+"X"+res+"]"
		togP=res+"["+gre+" "+res+"]"
	else:
		togR=res+"["+gre+" "+res+"]"
		togP=res+"["+gre+"X"+res+"]"


	text="   When targeting only "+cya+"Win10/11"+res+", the"+gre+" User_Shared_Data"+res+" or "+gre+"PEB"+res+" can determine OS build.\n"
	
	text+=yel+"   {}\t {}      {} {} Use the {} and {} to determine OS build.\n".format(cya+"1"+res,mag+"fs" +res, togF, "-"+yel,cya+"TEB"+yel, cya+"fs:[0x30]"+yel)
	text+=red+"\t\t\tSupported:"+res+" Windows 7-11\n"

	
	text+=yel+"   {}\t {}     {} {} Use {} to determine OS build.{}\n".format(cya+"2"+res,mag+"usd" +res,  togU,"-"+yel,cya+ "User_Shared_Data"+yel,res)
	text+=red+"\t\t\tSupported:"+res+" Windows 10-11\n"

	text+=yel+"   {}\t {}  {} {} Encode {} to determine OS build with XOR key {}.{}\n".format(cya+"3"+res,mag+"encode" +res,  togE,"-"+yel,cya+ "User_Shared_Data"+yel,cya+hex(sh.encodeUSDKey),res)
	text+=yel+"   {}\t {}     {} {} Change XOR key for encoding {}.\n".format(cya+"4"+res,mag+"xor" +res,togK,"-"+yel,cya+"User_Shared_Data"+res)
	text+=yel+"   {}\t {}     {} {} Get {} by adding {} to starting value, {}.{}\n".format(cya+"5"+res,mag+"add" +res,  togA,"-"+yel,cya+ "User_Shared_Data"+yel,gre+hex(sh.addUSDVal)+yel,cya+hex(0x7ffe0260 -sh.addUSDVal) +yel,res)
	text+=yel+"   {}\t {} {} {} Change value to add to get {}.{}\n".format(cya+"6"+res,mag+"add_val" +res,  togAV,"-"+yel,cya+ "User_Shared_Data"+yel,res)
	text+=yel+"   {}\t {}    {} {} Show this submenu.{}\n".format(cya+"h"+res,mag+"display" +res,  "","-"+res,res)

	text+=gre+"\n   Note:"+res+" The User_Shared_Data on "+cya+"Win7"+res+" does"+mag+" not"+res+" contain the OS Build, so this can only\n   be used if no Win7 OS builds are targeted. If selected, ShellWasp will use if allowable.\n"

	print (text)
def selectUserShared():			
	selectUserSharedOptions()
	userIN=""
	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ShellWasp>"+ cya+"Style>" + mag + "User_Shared_Data>" +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:2] == "fs":
				sh.useSharedData=False
				print ("  Use User_Shared_Data: ", mag+str(sh.useSharedData)+res)
			elif userIN[0:1] == "2" or userIN[0:16].lower() == "usd".lower() or userIN[0:3].lower() == "User".lower():
				if sh.useSharedData==False:
					sh.useSharedData=True
				else:
					sh.useSharedData=False
				print ("  Use User_Shared_Data: ", mag+str(sh.useSharedData)+res)
			elif userIN[0:1] == "3" or userIN[0:6].lower() == "encode".lower():
				if not sh.encodeUSD:
					sh.encodeUSD=True
				else:
					sh.encodeUSD=False
				print ("  Encode User_Shared_Data: ", mag+str(sh.encodeUSD)+res)
			elif userIN[0:1] == "4" or userIN[0:3].lower() == "xor".lower():
				hexInput=input("  Enter hexadecimal XOR key: ")
				try: 
					sh.encodeUSDKey=int(hexInput,16)
				except:
					try:
						sh.encodeUSDKey=int("0x"+hexInput,16)
					except:
						print (red+"   Unacceptable input."+res)
				print ("  XOR key: " + mag+hex(sh.encodeUSDKey)+res)
			elif userIN[0:1] == "5" or userIN[0:3].lower() == "add".lower():
				if not sh.addUSD:
					sh.addUSD=True
				else:
					sh.addUSD=False
				print ("  Add User_Shared_Data: ", mag+str(sh.encodeUSD)+res)				
			elif userIN[0:1] == "6" or userIN[0:7].lower() == "add_val".lower():
				print("   ShellWasp gets the {} by adding two values to get {}.".format(cya+"User_Shared_Data"+res, cya+"0x7ffe0260"+res))
				print("   Supply the value to be added; ShellWasp will calcuate the starting point.\n".format(cya+"User_Shared_Data"+res))

				hexInput=input("  Enter hexadecimal add value: ")
				temp=0
				try: 
					temp=int(hexInput,16)
					if len(hex(temp))>10:
						print ("  Input is too large.")
					elif temp>0x7ffe0260:
						print ("  Select a value less than "+cya+"0x7ffe0260."+res)
						continue
					else:
						sh.addUSDVal=temp
				except:
					try:
						temp=int("0x"+hexInput,16)
						if len(hex(temp))>10:
							print ("  Input is too large.")
						elif temp>0x7ffe0260:
							print ("  Select a value less than "+cya+"0x7ffe0260."+res)
							continue
						else:
							sh.addUSDVal=temp
					except:
						print (red+"   Unacceptable input."+res,temp )
				text="   ShellWasp will add {} to {} to get {}\n".format(mag + hex(sh.addUSDVal)+res, mag + hex(0x7ffe0260-sh.addUSDVal)+res, cya+"User_Shared_Data"+res )
				print(text)

			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				selectUserSharedOptions()
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")
def uiSyscallStyle():
	text = "  {} {} {}  {}   \n".format(cya + "s"+res,"-",gre+"Change syscall style."+ res, "[" +mag+sh.style +res+"]")
	if sh.style=="x64":
		text+=yel+"\tThis choice invokes Heaven's gate and executes {} instead of {} \n".format(cya+"x64 code"+yel, cya+"fs:[0xc0]"+res)
	elif sh.style=="fs":
		text+=yel+"\tThis choice invokes the syscall with {}\n".format(cya+"fs:[0xc0]"+res)
	text += "  {} {} {}  {}   \n".format(cya + "b"+res,"-",gre+"Change how x64 code is represented."+ res, "[" +mag+sh.intendedCompiler +res+"]")

	if sh.intendedCompiler=="nasm":
		text+=yel+"\tThis prepares x64 code in the style of {} - intended for compilers such as {} \n".format(cya+"db 0xde,0xad,0xbe,0xef"+yel, cya+"NASM"+res)
	elif sh.intendedCompiler=="inlineVS":
		text+=yel+"\tThis prepares x64 code for {} using emit, e.g. {}\n".format(cya+"VisualStudio inline Assembly"+yel,cya+"_emit 0xde"+res)
	text+=yel+"\tIf using x64 style, then we must transition from 32-bit to 64-bit code. {}\n".format(res)

	temp=[]
	if sh.useSharedData:
		temp.append("USD")
	if sh.user12Teb:
		temp.append("r12_PEB")
	else:
		temp.append("fs_PEB")


	if len(temp)==1:
		temp1=temp[0]
	else:
		temp1=""
		for each in temp:
			temp1+=cya+each+res+","
		temp1=temp1[:-1]
	tempOut="[{}]".format(cya+temp1+res)

	# text += "  {} {} {}  {}   \n".format(cya + "d"+res,"-",gre+"Use"+cya+" User_Shared_Data"+gre+" for Win10/11 to identify OS builds."+ res, togSD)
	text += "  {} {} {}  {} \n".format(cya + "o"+res,"-",gre+"Change how OSBuild is identified"+ res,tempOut)



	print (text)
	print("  Enter command to make changes. \n")

	print("  Type"+red+ " q " +res+"or "+red+ " x " +res+"to exit Style submenu.\n")
	userIN=""
	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ShellWasp>"+ cya+"Style> " + res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "x":
				break
			if userIN[0:1] == "q":
				break
			elif userIN[0:1] == "c" or userIN[0:1] == "s":
				selectSyscallStyle()
			elif userIN[0:1] == "o":
				selectFindOSBuild()
			elif userIN[0:1] == "b":
				selectCompilerStyle()
			elif userIN[0:1] == "h":	# "find assembly instrucitons associated with shellcode"
				uiSyscallStyle()
			elif userIN[0:1] == "d":	# "find assembly instrucitons associated with shellcode"
				# selectUserShared()
				selectFindOSBuild()

			
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")

		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")

	return
	while True:
		print (yel+ " ShellWasp>" + cya + "Style>" + res, end="")
		
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

def uiAddWinReleases():
	# self.win10ReverseLookup={"19044":"21h2, Win10", "19043":"21h1, Win10", "19042":"20h2, Win10", "19041":"2004, Win10", "18363":"1909, Win10", "18362":"1903, Win10", "17763":"1809, Win10", "17134":"1803, Win10", "16299":"1709, Win10", "15063":"1703, Win10", "14393":"1607, Win10", "10586":"1511, Win10", "10240":"1507"}
	checkWinOSBools()
	print (cya+"\nWindows 10:\t\t\t\tWindows 7:"+res)
	listWin10=["22h2", "21h2", "21h1", "20h2", "2004", "1909", "1903", "1809", "1803", "1709", "1703", "1607", "1511", "1507"]
	listWin10Back=["4A65", "4A64", "21h1", "20h2", "2004", "1909", "1903", "1809", "1803", "1709", "1703", "1607", "1511", "1507"]

	listWin11=["22h2","21h2"]
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
			t2="X2"
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
		print (yel+ " ShellWasp>" + cya + "WinReleases>" + res+ red + "Input>" +  res, end="")
		
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
		print (yel+ " ShellWasp>" + cya + "Syscalls>" + res+ red + "Input>" +  res, end="")
		
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
	# self.win10ReverseLookup={"19044":"21h2, Win10", "19043":"21h1, Win10", "19042":"20h2, Win10", "19041":"2004, Win10", "18363":"1909, Win10", "18362":"1903, Win10", "17763":"1809, Win10", "17134":"1803, Win10", "16299":"1709, Win10", "15063":"1703, Win10", "14393":"1607, Win10", "10586":"1511, Win10", "10240":"1507"}
	# 	self.win10ReverseLookupHex={"4A64": "21h2", "4A63": "21h1", "4A62": "20h2", "4A61": "2004", "47BB": "1909", "47BA": "1903", "4563": "1809", "42EE": "1803", "3FAB": "1709", "3AD7": "1703", "3839": "1607", "295A": "1511", "2800": "1507"}
	# 	# Win11 21h2 build 22000 55F0
	# 	self.win11ReverseLookupHex={"55F0":"21h2"}
	# 	self.win11ReverseLookup={"22000":"21h2, Win11"}
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
		print (yel+ " ShellWasp>" + cya + "Syscalls>" + res+ red + "Rearrange>" +  res, end="")
		
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
		print (yel+ " ShellWasp>" + cya + "WinReleases>" + res+ red + "Edit>" +  res, end="")
		
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
		print (yel+ " ShellWasp>" + cya + "Syscalls>" + res+ red + "Edit>" +  res, end="")
		
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
	text += "  {}        \n".format(cya + "p"+res+" -"+gre+"  Save current syscall shellcode to file."+ res)

	text += "  {}        \n".format(cya + "i"+res+" -"+gre+"  Add or modify syscalls."+ res)
	text += "  {}        \n".format(cya + "w"+res+" -"+gre+"  Add or modify Windows releases."+ res)
	text += "  {}        \n".format(cya + "s"+res+" -"+gre+"  Syscall style configuration."+ res)

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
		print(yel+ " ShellWasp>" + cya + "WinReleases> "+ res, end="")
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
		print(yel+ " ShellWasp>" + cya + "Syscalls> "+ res, end="")
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
	ks.syntax= KS_OPT_SYNTAX_NASM

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
			print(yel + " ShellWasp> " + res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "x":
				print("\nExiting program.\n")
				break
			
			elif userIN[0:1] == "i":
				giveInput()
			elif userIN[0:1] == "s":
				uiSyscallStyle()
			elif userIN[0:1] == "b":
				out=buildSyscall()
				print(out)
			elif userIN[0:1] == "p":	
				buildSyscall(True)
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
	# out=buildSyscall(True)
	# print(out)
	ui()
sConf=configOpt()
sh = shellcode()
builds=winReleases()
syscalls=winSyscalls()
sRaw=shellBytes()