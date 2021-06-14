import sys
from pathlib import Path

from JasonUtils.TicToc import timing

from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import pcaps2timeSeriesDatasets


@timing
def main():
    pcapFolder = '/Users/jinliu/Desktop/CICIDS2017/PCAPs'
    outputFolder = '/Users/jinliu/Desktop/CICIDS2017/TimeSeries'
    if len(sys.argv) > 1:
        assert len(sys.argv) == 3, \
            f'Invalid format: {sys.argv}. python main.py PCAP_Folder Output_Folder'
        _, pcapFolder, outputFolder = sys.argv
    elif pcapFolder == '' or pcapFolder is None:
        pcapFolder = input(f'PCAP Folder Path: ')
        outputFolder = input(f'Output Folder Path: ')
    pcaps2timeSeriesDatasets(pcapFolder, outputFolder, keep_packets=False)


if __name__ == '__main__':
    with backend('pyshark'):
        main(timerPrefix='Total Time Costs: ', timerBeep=True)
