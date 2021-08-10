import sys

from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import pcaps2timeSeriesDatasets, pcaps2csvs


def main():
    # pcapFolder = '/Users/jinliu/Desktop/CICIDS2017/PCAPs'
    # outputFolder = '/Users/jinliu/Desktop/CICIDS2017/TimeSeries'
    pcapFolder = 'E:\CICIDS2018\Friday-02-03-2018-pcap\pcap'
    outputFolder = 'E:\CICIDS2018\Friday-02-03-2018-pcap\csv'
    if len(sys.argv) > 1:
        assert len(sys.argv) == 3, \
            f'Invalid format: {sys.argv}. python main.py PCAP_Folder Output_Folder'
        _, pcapFolder, outputFolder = sys.argv
    elif pcapFolder == '' or pcapFolder is None:
        pcapFolder = input(f'PCAP Folder Path: ')
        outputFolder = input(f'Output Folder Path: ')
    # pcaps2timeSeriesDatasets(pcapFolder, outputFolder, keep_packets=False)
    pcaps2csvs(pcapFolder, outputFolder)


if __name__ == '__main__':
    with backend('scapy'):
        main()
