from typing import Tuple, List

from TimeSeriesNetworkFlowMeter.Config import getConfig
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, FlowFeaturePrefix
from TimeSeriesNetworkFlowMeter.Flow import Flow
from TimeSeriesNetworkFlowMeter.Typing import Features
from TimeSeriesNetworkFlowMeter.Utils import addStatChar2Dict


class ActiveIdle(FeatureExtractor):
    def __init__(self, activityTimeout=None):
        super(ActiveIdle, self).__init__()
        self._activityTimeout = float(getConfig().get('Feature', 'activity timeout')) \
            if activityTimeout is None else activityTimeout

    def getActiveIdleLists(self, flow: Flow) -> Tuple[List[float], List[float]]:
        activeList, idleList = list(), list()
        initPacket = lastPacket = None
        for index, p in enumerate(flow.packets):
            if initPacket is None:
                initPacket = p
            elif p.getTs() - lastPacket.getTs() > self._activityTimeout:
                activeList.append(lastPacket.getTs() - initPacket.getTs())
                idleList.append(p.getTs() - lastPacket.getTs())
                initPacket = None
            lastPacket = p
        if initPacket is not None:
            activeList.append(lastPacket.getTs() - initPacket.getTs())
        return activeList, idleList

    def extract(self, flow: Flow) -> Features:
        features = dict()
        activeList, idleList = self.getActiveIdleLists(flow)
        addStatChar2Dict(
            features,
            f'{FlowFeaturePrefix} Active',
            activeList
        )
        addStatChar2Dict(
            features,
            f'{FlowFeaturePrefix} Idle',
            idleList
        )
        return features
