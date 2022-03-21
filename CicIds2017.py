import sys

from TimeSeriesNetworkFlowMeter.Flow import DefaultEarliness, DefaultEarlinessDuration, FlowWithEarliness
from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import pcaps2timeSeriesDatasets, pcaps2csvs, \
    pcaps2packetTimeSeriesDatasets, pcap2csv


def main():
    earliness, earlinessDuration = DefaultEarliness, DefaultEarlinessDuration
    pcapFolder = f'/Users/jinliu/Desktop/CICIDS2017/PCAPs'
    outputFolder = f'/Users/jinliu/Desktop/CICIDS2017/CSV_{earliness}_{earlinessDuration}'
    # pcapFolder = r'E:\CICIDS2018\Friday-02-03-2018-pcap\pcap'
    # outputFolder = r'E:\CICIDS2018\Friday-02-03-2018-pcap\csv'
    if len(sys.argv) > 1:
        assert len(sys.argv) == 3, \
            f'Invalid format: {sys.argv}. python main.py PCAP_Folder Output_Folder'
        _, pcapFolder, outputFolder = sys.argv
    elif pcapFolder == '' or pcapFolder is None:
        pcapFolder = input(f'PCAP Folder Path: ')
        outputFolder = input(f'Output Folder Path: ')
    # pcaps2timeSeriesDatasets(pcapFolder, outputFolder, keep_packets=False)
    pcaps2csvs(pcapFolder, outputFolder, FlowType=FlowWithEarliness)
    # pcap2csv(f'/Users/jinliu/Desktop/CICIDS2017/PCAPs/Tuesday-WorkingHours.pcap', f'/Users/jinliu/Desktop/CICIDS2017/CSV_10_0.1/Tuesday-WorkingHours.csv', FlowType=FlowWithEarliness)
    # pcaps2packetTimeSeriesDatasets(pcapFolder, outputFolder)


if __name__ == '__main__':
    with backend('scapy'):
        main()
