#!/usr/bin/env python3

#####################################################
# 04.06.2020
#
# This code calculates packet error rates from
# 802.11 PCAP traces.
#
# Author: Aygün Baltaci
#
# License: GNU General Public License v3.0
#####################################################

from datetime import datetime
import math
import os
import pandas as pd
from scapy.all import *

# ======== variables
inputDir = 'inputfiles'
inputFileName = "input_per.pcap"
perInputFileName = "input_per.csv" # use this command to generate sqn list file: 'tshark -r flight4_wifi_ul.pcap -e frame.time_relative -e wlan.seq -Tfields | tee sqn.csv'
outputFileBeginWord = 'ul_' # measurement channel. downlink or uplink

# variables for calculate_bps()
startPkt = 0 # packet num of the packet which you want to begin the calculations

# variables for calculate_per()
leftoverTime_freq = 1000 # how often elapsed and leftover time to be printed on the terminal. Once per # of loops, # of loops to be defined here
fileDate = datetime.now().strftime('%Y%m%d_%H%M%S_')
inputDir = 'inputfiles'
outputDir = 'outputfiles'
outputFile = 'PER'
outputFileSort = 'pkts_sorted'
outputFileLoss = 'lossPkts'
outputFileFormat = '.csv'
outputFileName = outputFileBeginWord + fileDate + outputFile + outputFileFormat
outputFileNameSort = outputFileBeginWord + fileDate + outputFileSort + outputFileFormat
outputFileNameLoss = outputFileBeginWord + fileDate + outputFileLoss + outputFileFormat

# ======== modify sniffed packets
def packetStats():
    sqnNum = 0 
    prevSqnNum = 0
    pktLossCnt = 0
    prevTime = 0
    timeStamp = 0
    secCnt = 0
    numPktsPerSec = []
    pktLossPerSec = []
    prevPktCount = 0
    pktCount = 0
    cutData_sqn = []
    cutData_time = []
    organizedData = pd.DataFrame()
    
    pkts=rdpcap(inputDir + os.sep + inputFileName)
    data = pd.read_csv(inputDir + os.sep + perInputFileName)
    
    prevSqnNum = data.iloc[0, 1]
    timeStampRef = int(pkts[0].time)
    timeStampRef2 = int(pkts[0].time)
    
    with open(outputDir + os.sep + outputFileName, 'a') as outputFile:
        outputFile.write('Time, Total Number of Packets, Loss Packets, PER (%)\n')
    
    # calculate # of packets per second
    pktSqnNum = data.iloc[0, 1]
    maxSqnNum = 0
    minSqnNum = 99999
    
    for pkt in pkts:
        pktSqnNum = data.iloc[pktCount, 1]
        pktCount += 1
        timeStamp = int(pkt.time)
        if int(timeStamp) - int(timeStampRef2) >= 1: 
            numPktsPerSec.append(maxSqnNum - minSqnNum)
            print("Time: %d, minSqnNum: %d, maxSqnNum: %d" %(timeStampRef2, minSqnNum, maxSqnNum))
            if int(timeStamp) - int(timeStampRef2) > 1:
                for j in range(int(timeStamp) - int(timeStampRef2) - 1):
                    numPktsPerSec.append(0.1) # 0.1 just to avoid 0 division error
            timeStampRef2 = int(timeStamp)
            maxSqnNum = 0
            minSqnNum = 99999
        if pktSqnNum > maxSqnNum:
            maxSqnNum = pktSqnNum
        if pktSqnNum < minSqnNum:
            minSqnNum = pktSqnNum
            
    for i in range(len(numPktsPerSec)):
        pktLossPerSec.append(0)
    
    with open(outputDir + os.sep + outputFileNameLoss, 'w') as file_losspkts:
        file_losspkts.write('Time, Loss SQN\n')

        for m in range (len(data.iloc[:, 1])):
            cutData_time.append(data.iloc[m, 0])
            cutData_sqn.append(data.iloc[m, 1])
            if data.iloc[m, 1] == 4095 or data.iloc[m, 0] == data.iloc[-1, 0]:
                insertData = {'time': cutData_time, 'sqn': cutData_sqn}
                organizedData = pd.DataFrame(insertData)
                organizedData = organizedData.sort_values('sqn')
                organizedData.to_csv(outputDir + os.sep + outputFileNameSort, mode = 'a')
                cutData_time, cutData_sqn = [], []
                
                # calculate # of loss packets per second
                for i in range (len(organizedData['sqn'])):
                    if not math.isnan(organizedData['sqn'].values[i]): # ignore empty cells in csv
                        sqnNum = organizedData['sqn'].values[i]
                        if sqnNum - prevSqnNum >= 1:
                            if sqnNum - prevSqnNum > 1:
                                for j in range (int(sqnNum) - int(prevSqnNum) - 1):
                                    pktLossPerSec[int(organizedData['time'].values[i - 1])] += 1
                                    file_losspkts.write('%f, %d \n' %(organizedData['time'].values[i - 1], sqnNum - j - 1))
                                    print("lost packet: t = %f, sqnNum = %d" %(organizedData['time'].values[i - 1], (sqnNum - j - 1)))    
                        prevSqnNum = sqnNum
    with open(outputDir + os.sep + outputFileName, 'a') as outputFile:
        for l in range (len(numPktsPerSec)):
            outputFile.write('%d, %d, %d, %f\n' %(l + 1, numPktsPerSec[l], pktLossPerSec[l], (pktLossPerSec[l]/numPktsPerSec[l]) * 100))
            
    print("\n\nDONE!")     
packetStats()