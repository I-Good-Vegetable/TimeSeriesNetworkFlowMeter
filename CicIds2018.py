from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import pcap2csv


def main():

    fileDict = {
        '/Users/jinliu/Desktop/CICIDS2018/UCAP172.31.69.25.pcap':
            '/Users/jinliu/Desktop/CICIDS2018/UCAP172.31.69.25.csv',
        '/Users/jinliu/Desktop/CICIDS2018/UCAP172.31.69.28 part 2.pcap':
            '/Users/jinliu/Desktop/CICIDS2018/UCAP172.31.69.28 part 2.csv',
    }
    for pcapFile, csvFile in fileDict.items():
        pcap2csv(pcapFile, csvFile)


if __name__ == '__main__':
    with backend('scapy'):
        main()
