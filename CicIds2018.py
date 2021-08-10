import sys

from joblib import Parallel, delayed
from tqdm import tqdm

from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import pcaps2timeSeriesDatasets, pcaps2csvs, pcap2csv


def main():

    fileDict = {
        'E:/CICIDS2018/Tuesday-20-02-2018-pcap/pcap/UCAP172.31.69.25.pcap':
            'E:/CICIDS2018/Tuesday-20-02-2018-pcap/csv/UCAP172.31.69.25.csv',
        'E:/CICIDS2018Wednesday-21-02-2018-pcap/pcap/UCAP172.31.69.28 part 2.pcap':
            'E:/CICIDS2018/Wednesday-21-02-2018-pcap/csv/UCAP172.31.69.28 part 2.csv',

    }
    for pcapFile, csvFile in fileDict.items():
        pcap2csv(pcapFile, csvFile)


if __name__ == '__main__':
    with backend('scapy'):
        main()
