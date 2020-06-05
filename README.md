# Packet Error Rate Calculator for 802.11 PCAP Traces

These scripts calculate Packet Error Rate (PER) of PCAP data traces in 802.11 protocol. Based on the Packet Sequence Numbers (PSNs) of the collected data, it detects the missing PSNs and estimates PER in a second resolution. It is an estimation since the methods explained above are prone to errors due to late packet arrivals. 

These programs can be useful if you need to estimate PER from your measurements, based on packet sequence numbers. 

## PER Computation Algorithms

**Method 1 (*compute_per_method1.py*)**:
1. *Calculation of Total Number of Packets*: At each second, count total number of received packets in Wireshark trace. Add number of loss packets from Step 2 below to the received packet count to calculate the total number of packets per second. 
2. *Detection of Loss Packets*: At each second interval, when *PSN = 4095* (because PSN counter is up to 2^12) or *timestamp_new - timestamp_prev > 1* (*timestamp_prev*: Timestamp of previous packet, *timestamp_new*: Timestamp of the current packet, reorder all the previous PSNs according to their number and detect missing PSNs. Repeat this process until all packets are checked at each second. 

**Method 2 (*compute_per_method2.py*)**:
1. *Calculation of Total Number of Packets*: Detect the minimum (*psn_min*) and maximum PSN (*psn_max*) at each second interval in Wireshark trace. Then, calculate total number of packets at each second as *num_of_packets = psn_max - psn_min* 
2. *Detection of Loss Packets*: At each second interval, when *PSN = 4095* (because PSN counter is up to 2^12), reorder all the previous PSNs according to their number and detect missing PSNs. Repeat this process until all packets are checked at each second. 

**Method 3 (*compute_per_method3.py*)**
1. *Calculation of Total Number of Packets*: At each second, count total number of received packets in Wireshark trace. Add number of loss packets from Step 2 below to the received packet count to calculate the total number of packets per second. 
2. *Detection of Loss Packets*: At each second interval, when *PSN = 4095* (because PSN counter is up to 2^12), reorder all the previous PSNs according to their number and detect missing PSNs. Repeat this process until all packets are checked at each second. 

Method 3 is a combination of Method 1 and Method 2. It seems to be the best working algorithm so far. 

### Flaws of the Algorithms
Each method has certain advantages and disadvantages in estimating the PER: 
**Method 1**: 
- Detection of loss packets is prone to error if the packet with PSN 4095 is also lost
- If the gap between the PSN of previous and current packets is > 100, it won't count them as loss packets (need to manually have a look at the data trace to find out what happened)

**Method 2**:
- Packet counter is prone to error (e.g. When the PSN of previous packet is 3000 and the current PSN is 20, the program cannot know whether total number of packets is 3000 - 20 = 2980 (packet with PSN 20 is late arrival) or 4095 - 3000 + 20 (PSN counter restarted from 0)
- Detection of loss packets is prone to error if the packet with PSN 4095 is also lost

**Method 3**:
- Detection of loss packets is prone to error if the packet with PSN 4095 is also lost

## Prerequisites
**Python 3**
> sudo apt update

> sudo apt install python3.6 (or any other python3 version) 

**Csv and numpy libraries**
> pip3 install csv numpy

## Input Files
Please use the command below to extract the Time and PSN data from your PCAP trace: 
> tshark -r <pcap-file-name>.pcap -e frame.time_relative -e wlan.seq -Tfields | tee input_per.csv

**inputfiles/input_per.csv**: The dataset used for all methods, where Time and PSN numbers are saved from PCAP trace. 

**inputfiles/input_per.pcap**: Used only by method2 to compute number of packets per second. 

## Usage
> python3 computer_per_method1.py

> python3 computer_per_method2.py

> python3 computer_per_method3.py

## Result
The result is saved in the directory below with the corresponding date (YYYYMMDD_HHMMSS):
*outputfiles/*

**_lossPkts**: The missing PSNs in the data trace (= PSNs of the loss packets)

***_PER**: Packet error rate results (along with total number of packets and total number of lost packets per second)

***_pkts_sorted**: Recorded packets that are sorted with respect to their PSNs 

Perform *Text to Columns* conversion with *space* character as delimeter on the output csv file. 

## Copyright
This code is licensed under GNU General Public License v3.0. For further information, please refer to [LICENSE](LICENSE)