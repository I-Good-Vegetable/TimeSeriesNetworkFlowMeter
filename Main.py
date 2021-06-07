from JasonUtils.TicToc import timing

from TimeSeriesNetworkFlowMeter.NetworkBackend import backend
from TimeSeriesNetworkFlowMeter.NetworkFlowMeter import packets2featureSet
from TimeSeriesNetworkFlowMeter.PCAP import pcap2generator
from TimeSeriesNetworkFlowMeter.Session import FlowSessionManager
from TimeSeriesNetworkFlowMeter.Utils import sortFeatureSet, featureSet2csv, featureSet2mat, sortFeatureMat, \
    featureMat2csv, featureSet2df, sortFeatureDf, featureDf2csv


@timing
def main():
    pcapPath = 'Data/PCAP/Test.pcap'
    csvPath = 'Data/CSV/Test.csv'

    featureSet = packets2featureSet(pcap2generator(pcapPath), FlowSessionManager(), None)

    featureSet2csv(csvPath, featureSet)

    # featureMat, featureNames = featureSet2mat(featureSet, True)
    # featureMat2csv(csvPath, featureMat, featureNames)
    #
    # featureDf = featureSet2df(featureSet)
    # featureDf2csv(csvPath, featureDf)
    pass


if __name__ == '__main__':
    with backend('pyshark'):
        main(timerPrefix='Total Time Costs: ', timerBeep=True)
