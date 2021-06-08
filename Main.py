from JasonUtils.TicToc import timing

from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import packets2featureSet
from TimeSeriesNetworkFlowMeter.PCAP import pcap2generator
from TimeSeriesNetworkFlowMeter.Session import FlowSessionManager
from TimeSeriesNetworkFlowMeter.Utils import sortFeatureSet, featureSet2csv, featureSet2mat, sortFeatureMat, \
    featureMat2csv, featureSet2df, sortFeatureDf, featureDf2csv


@timing
def main():
    pass


if __name__ == '__main__':
    with backend('pyshark'):
        main(timerPrefix='Total Time Costs: ', timerBeep=True)
