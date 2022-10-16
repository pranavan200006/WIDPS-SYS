#!/usr/bin/python3


import shlex

IMPORT_ERRMSG=""
import builtins
import os,sys,subprocess,getopt,glob
import time,datetime
import tty,termios,curses
import select
import signal
import random
import urllib.request, urllib.parse, urllib.error
import shutil
import re
import readline
import threading
from signal import SIGINT, SIGTERM
from subprocess import Popen, call, PIPE
from sys import stdout, stdin
from math import floor

appver="1.0, R.6k"
apptitle="WIDPS"
appDesc="- The Wireless Intrusion Detection & Prevention System"
appcreated="16 October 2022" #change the date 
appupdated=""
appmodified=""  
appnote="Written By Haseef Ahmed and Prenavan, " + appcreated + ", Updated on " + appupdated +
appdescription="Wiresless Intrusion Detection & Prevention System is a whole new application which is design to harvest all WiFi information (AP / Station details) in your surrounding and store as a database for reference. With the stored data, user can further lookup for specific MAC or names for detailed information of it relation to other MAC addresses. It primarily purpose is to detect wireless attacks in WEP/WPA/WPS encryption. It also comes with an analyzer and viewer which allow user to further probe and investigation on the intrusion/suspicious packets captured. Additional features such as blacklisting which allow user to monitor specific MACs/Names's activities. All information captured can also be saved into pcap files for further investigation."
class fcolor:
    CReset='\033[0m'
    CBold='\033[1m'
    CDim='\033[2m'
    CUnderline='\033[4m'
    CBlink='\033[5m'
    CInvert='\033[7m'
    CHidden='\033[8m'
    CDebugB='\033[1;90m'
    CDebug='\033[0;90m'
    Black='\033[0;30m'
    Red='\033[0;31m'
    Green='\033[0;32m'
    Yellow='\033[0;33m'
    Blue='\033[0;34m'
    Pink='\033[0;35m'
    Cyan='\033[0;36m'
    White='\033[0;37m'
    SBlack=CReset + '\033[30m'
    SRed=CReset + '\033[31m'
    SGreen=CReset + '\033[32m'
    SYellow=CReset + '\033[33m'
    SBlue=CReset + '\033[34m'
    SPink=CReset + '\033[35m'
    SCyan=CReset + '\033[36m'
    SWhite=CReset + '\033[37m'
    BBlack='\033[1;30m'
    BRed='\033[1;31m'
    BBlue='\033[1;34m'
    BYellow='\033[1;33m'
    BGreen='\033[1;32m'
    BPink='\033[1;35m'
    BCyan='\033[1;36m'
    BWhite='\033[1;37m'
    UBlack='\033[4;30m'
    URed='\033[4;31m'
    UGreen='\033[4;32m'
    UYellow='\033[4;33m'
    UBlue='\033[4;34m'
    UPink='\033[4;35m'
    UCyan='\033[4;36m'
    UWhite='\033[4;37m'
    BUBlack=CBold + '\033[4;30m'
    BURed=CBold + '\033[4;31m'
    BUGreen=CBold + '\033[4;32m'
    BUYellow=CBold + '\033[4;33m'
    BUBlue=CBold + '\033[4;34m'
    BUPink=CBold + '\033[4;35m'
    BUCyan=CBold + '\033[4;36m'
    BUWhite=CBold + '\033[4;37m'
    IGray='\033[0;90m'
    IRed='\033[0;91m'
    IGreen='\033[0;92m'
    IYellow='\033[0;93m'
    IBlue='\033[0;94m'
    IPink='\033[0;95m'
    ICyan='\033[0;96m'
    IWhite='\033[0;97m'
    BIGray='\033[1;90m'
    BIRed='\033[1;91m'
    BIGreen='\033[1;92m'
    BIYellow='\033[1;93m'
    BIBlue='\033[1;94m'
    BIPink='\033[1;95m'
    BICyan='\033[1;96m'
    BIWhite='\033[1;97m'
    BGBlack='\033[40m'
    BGRed='\033[41m'
    BGGreen='\033[42m'
    BGYellow='\033[43m'
    BGBlue='\033[44m'
    BGPink='\033[45m'
    BGCyan='\033[46m'
    BGWhite='\033[47m'
    BGIBlack='\033[100m'
    BGIRed='\033[101m'
    BGIGreen='\033[102m'
    BGIYellow='\033[103m'
    BGIBlue='\033[104m'
    BGIPink='\033[105m'
    BGICyan='\033[106m'
    BGIWhite='\033[107m'


def RemoveColor(InText):
    return color_pattern.sub('',InText);

def BeepSound():
    if builtins.ALERTSOUND=="Yes":
        sys.stdout.write("\a\r")
        sys.stdout.flush()

def read_a_key():
    stdinFileDesc = sys.stdin.fileno()
    oldStdinTtyAttr = termios.tcgetattr(sstdinFileDesc)
    try:
        tty.setraw(stdinFileDesc)
        sys.stdin.read(1)
    finally:
        termios.tcsetattr(stdinFileDesc, termios.TCSADRAIN, oldStdinTtyAttr)

def CheckAdmin():
    if os.getuid() != 0:
        printc ("!!!",fcolor.BGreen + apptitle + " required administrator rights in order to run properly !","")
        printc ("!!!",fcolor.SGreen + "Log in as '" + fcolor.BRed + "root" + fcolor.SGreen + "' user or run '" + fcolor.BRed + "sudo ./" + builtins.ScriptName + fcolor.SGreen + "'","")
#        exit_gracefully(1)
        exit()

def DropFiles():
    with open(builtins.ScriptFullPath,"r", encoding="UTF-8", errors="backslashreplace") as f:
        READSTATUS=""
        for line in f:
            line=line.replace("\n","")
            if line!="":
                if line=="##--DropFile--##":
                    READSTATUS="START"
                if line=="##--EndFile--##":
                    READSTATUS=""
                    shutil.copy2(appdir + DropFileName, "/usr/sbin/" + str(DropFileName))
                    result=os.system("chmod +x /usr/sbin/" + DropFileName + " > /dev/null 2>&1")
                    result=os.system("chmod +x " + appdir + DropFileName + " > /dev/null 2>&1")
                if line=="##--StopRead--##":
                    return;
                if READSTATUS=="WRITE":
# For Python 3
#                    open(appdir + DropFileName,"a+b").write(line[2:] + "\n")
                    open(appdir + DropFileName,"a", encoding="UTF-8").write(line[2:] + "\n")
                if READSTATUS=="START" and len(line)>15 and str(line)[:13]=="##--FileName:":
                    DropFileName=str(line)[13:]
                    DropFileName=DropFileName
# For Python 3
                    open(appdir + DropFileName,"w", encoding="UTF-8").write("")
                    READSTATUS="WRITE"


def AboutApplication():
    os.system('clear')
    WordColor=fcolor.BCyan
    print(fcolor.BGreen + "db   d8b   db d888888b d8888b. d8888b. .d8888.")
    print(fcolor.BGreen + "88   I8I   88   `88'   88  `8D 88  `8D 88'  YP")
    print(fcolor.BGreen + "88   I8I   88    88    88   88 88oodD' `8bo.  ")
    print(fcolor.BGreen + "Y8   I8I   88    88    88   88 88~~~     `Y8b.")
    print(fcolor.BGreen + "`8b d8'8b d8'   .88.   88  .8D 88      db   8D")
    print(fcolor.BGreen + " `8b8' `8d8'  Y888888P Y8888D' 88      `8888Y'")
    ShowSYWorks()
    print("");print("")
    print(fcolor.BGreen + apptitle + " " + appver + fcolor.SGreen + " " + appDesc)
    print(fcolor.CReset + fcolor.White + appnote)
    print("")
    DisplayDescription()
    print("")

# added by 
    print(fcolor.BGreen + "Written By Haseef Ahmed and Prenavan") #add website of the tool

    print("");print("")
    printc ("x",fcolor.BRed + "Press a key to continue...","")
    LineBreak()

def LineBreak():
    DrawLine("_",fcolor.CReset + fcolor.SWhite,"","");print("");

