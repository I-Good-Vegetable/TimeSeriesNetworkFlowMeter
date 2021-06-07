from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, addFlowStatFeatures
from TimeSeriesNetworkFlowMeter.Flow import Flow
from TimeSeriesNetworkFlowMeter.Typing import Features


class InterArrivalTime(FeatureExtractor):

    def extract(self, flow: Flow) -> Features:
        features = dict()
        addFlowStatFeatures(
            features,
            flow,
            'Iat',
            pktListOperator=lambda pl: [pl[i].getTs() - pl[i - 1].getTs()
                                        for i in range(1, len(pl))]
        )
        return features
