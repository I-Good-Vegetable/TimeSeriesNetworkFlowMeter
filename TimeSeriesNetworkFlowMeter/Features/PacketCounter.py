from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, addFlowStatFeatures, \
    addFlowCountSpeedFeatures
from TimeSeriesNetworkFlowMeter.Flow import Flow
from TimeSeriesNetworkFlowMeter.Typing import Features


class PacketCounter(FeatureExtractor):

    def extract(self, flow: Flow) -> Features:
        features = dict()
        addFlowStatFeatures(
            features,
            flow,
            'Pkt Len',
            pktOperator=lambda p: p.getLen()
        )
        addFlowCountSpeedFeatures(
            features,
            flow,
            'Pkt',
            len,
        )
        addFlowCountSpeedFeatures(
            features,
            flow,
            'Byte',
            lambda pl: sum(p.getLen() for p in pl),
        )
        return features
