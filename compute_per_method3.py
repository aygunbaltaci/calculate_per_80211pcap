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

# ======== variables
inputDir = 'inputfiles'
perInputFileName = "input_per.csv" # use this command to generate sqn list file: 'tshark -r flight4_wifi_ul.pcap -e frame.time_relative -e wlan.seq -Tfields | tee sqn.csv'
outputFileBeginWord = 'dl_' # measurement channel. downlink or uplink
maxPSN = 4095
lateArrival_threshold = 45 # number of packets that can arrive late. Used to correctly calculate number of packets and packet loss. Because, late arrivals can mess up the calculations (e.g. if a packet with PSN 4095 arrives after a packet with PSN 0, then calculators will think there are 4094 lost packets).

# variables for calculate_bps()
startPkt = 0 # packet num of the packet which you want to begin the calculations

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

def writeNumOfPackets(minSqnNum, maxSqnNum, pktCount2, timeStampRef2, numPktsPerSec): 
    if minSqnNum == 99999 and maxSqnNum == 0: # there is no packet with PSN during the time interval
        minSqnNum = 0 
        maxSqnNum = 0
    if maxSqnNum != minSqnNum:
        pktCount2 += maxSqnNum - minSqnNum + 1 # if they are equal, that means there is only 1 packet
    numPktsPerSec.append(pktCount2)
    print("Time: %d, # of packets: %d" %(timeStampRef2, pktCount2))
    minSqnNum = 99999
    maxSqnNum = 0
    pktCount2 = 0 
    return numPktsPerSec, minSqnNum, maxSqnNum, pktCount2

# ======== modify sniffed packets
def packetStats():
    sqnNum = 0 
    prevSqnNum = 0
    prevSqnNum2 = 0
    pktLossCnt = 0
    prevTime = 0
    timeStamp = 0
    secCnt = 0
    numPktsPerSec = []
    pktLossPerSec = []
    lastPSNPerSec = []
    prevPktCount = 0
    pktCount = 0
    pktCount2 = 0
    cutData_sqn = []
    cutData_time = []
    organizedData = pd.DataFrame()

    data = pd.read_csv(inputDir + os.sep + perInputFileName)
    
    # write header to output file
    with open(outputDir + os.sep + outputFileName, 'a') as outputFile:
        outputFile.write('Time, Total Number of Packets, Loss Packets, PER (%)\n')

    # find the first PSN
    for k in range(len(data.iloc[:, 1])):
        if not math.isnan(data.iloc[k, 1]):
            prevSqnNum = data.iloc[k, 1]
            prevSqnNum2 = data.iloc[k, 1]
            break

    timeStampRef2 = int(data.iloc[0, 0])

    # calculate number of seconds
    for i in range(len(data.iloc[:, 0])):
        timeStamp = int(data.iloc[i, 0]) 
        if int(timeStamp) - int(timeStampRef2) >= 1: 
            for j in range(int(timeStamp) - int(timeStampRef2)):
                secCnt += 1
                timeStampRef2 = int(timeStamp)

    # initialize empty arrays 
    for i in range(secCnt):
        numPktsPerSec.append(0)
        pktLossPerSec.append(0)

    # calculate # of rx packets per second
    timeStampRef2 = int(data.iloc[0, 0])
    secCnt = 0
    for i in range(len(data.iloc[:, 0])):
        pktCount += 1 
        timeStamp = int(data.iloc[i, 0])
        if int(timeStamp) - int(timeStampRef2) >= 1:
            numPktsPerSec[secCnt] = pktCount
            if int(timeStamp) - int(timeStampRef2) > 1:
                for j in range(int(timeStamp) - int(timeStampRef2) - 1):
                    secCnt += 1  
                    numPktsPerSec[secCnt] = 0.1 # 0.1 just to avoid 0 division error
            print("Time: %d, num of pkts: %d" %(secCnt, pktCount))        
            timeStampRef2 = int(timeStamp)
            pktCount = 0
            secCnt += 1  

    with open(outputDir + os.sep + outputFileNameLoss, 'w') as file_losspkts:
        file_losspkts.write('Time, Loss SQN\n')

        for m in range (len(data.iloc[:, 1])):
            cutData_time.append(data.iloc[m, 0])
            cutData_sqn.append(data.iloc[m, 1])
            if data.iloc[m, 1] == 4095 or data.iloc[m, 0] == data.iloc[-1, 0]:
                insertData = {'time': cutData_time, 'sqn': cutData_sqn}
                organizedData = pd.DataFrame(insertData)
                organizedData = organizedData.sort_values('sqn')
                organizedData.to_csv(outputDir + os.sep + outputFileNameSort, mode = 'a', index = False)
                cutData_time, cutData_sqn = [], []
                
                # calculate # of loss packets per second
                for i in range (len(organizedData['sqn'])):
                    if not math.isnan(organizedData['sqn'].values[i]): # ignore empty cells in csv
                        sqnNum = organizedData['sqn'].values[i]
                        if sqnNum - prevSqnNum >= 1:
                            if sqnNum - prevSqnNum > 1:
                                for j in range (int(sqnNum) - int(prevSqnNum) - 1):
                                    pktLossPerSec[int(organizedData['time'].values[i - 1])] += 1
                                    numPktsPerSec[int(organizedData['time'].values[i - 1])] += 1
                                    file_losspkts.write('%f, %d \n' %(organizedData['time'].values[i - 1], sqnNum - j - 1))
                                    print("lost packet: t = %f, sqnNum = %d" %(organizedData['time'].values[i - 1], (sqnNum - j - 1)))             
                        prevSqnNum = sqnNum
    with open(outputDir + os.sep + outputFileName, 'a') as outputFile:
        for l in range (len(numPktsPerSec)):
            outputFile.write('%d, %d, %d, %f\n' %(l + 1, numPktsPerSec[l], pktLossPerSec[l], (pktLossPerSec[l]/numPktsPerSec[l]) * 100))

    print("\n\nDONE!")     
packetStats()
