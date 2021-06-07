from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, addFlowCountSpeedFeatures

from TimeSeriesNetworkFlowMeter.Flow import Flow
from TimeSeriesNetworkFlowMeter.Typing import Features


class TcpFlagCounter(FeatureExtractor):

    def extract(self, flow: Flow) -> Features:
        features = dict()
        for flagName in AbstractPacketBase.getTcpFlagNames():
            addFlowCountSpeedFeatures(
                features,
                flow,
                flagName,
                lambda pl: sum(p.getTcpFlag(flagName) for p in pl)
            )
        return features
