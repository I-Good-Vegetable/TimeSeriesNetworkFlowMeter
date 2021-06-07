from typing import List, Union, Iterable, Callable, Any, Collection

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase
from TimeSeriesNetworkFlowMeter.Config import getConfig
from TimeSeriesNetworkFlowMeter.Flow import Flow, EmptyFlow
from TimeSeriesNetworkFlowMeter.Log import logger
from TimeSeriesNetworkFlowMeter.Session import Unidirectional, Bidirectional
from TimeSeriesNetworkFlowMeter.Typing import Features, AbstractPacketList
from TimeSeriesNetworkFlowMeter.Utils import addStatChar2Dict

ForwardFeaturePrefix = getConfig().get('Feature', 'forward feature prefix')
BackwardFeaturePrefix = getConfig().get('Feature', 'backward feature prefix')
RatioFeaturePrefix = getConfig().get('Feature', 'ratio feature prefix')
FlowFeaturePrefix = getConfig().get('Feature', 'flow feature prefix')
BidirectionalFeaturePrefix = (
    ForwardFeaturePrefix,
    BackwardFeaturePrefix,
    RatioFeaturePrefix,
)
UnidirectionalFeaturePrefix = (
    FlowFeaturePrefix,
)


def checkFeatureDirection(featureName: str):
    """
    Check the direction of given feature name

    :param featureName: The feature name
    :return: Bidirectional, Unidirectional, and None (basic info)
    """
    direction = None
    if featureName.startswith(BidirectionalFeaturePrefix):
        direction = Bidirectional
    elif featureName.startswith(UnidirectionalFeaturePrefix):
        direction = Unidirectional
    return direction


class FeatureNameException(Exception):
    pass


class FeatureExtractor:
    def __init__(self):
        """
        This supper class method must be invoked at the end of sub-class init function
        """
        self._enable = True
        try:
            self.featureNames = self.getFeatureNames()
        except FeatureNameException:
            self.featureNames = list(self.extract(EmptyFlow).keys())

    def getFeatureNames(self):
        raise FeatureNameException(
            f'Implementation is not mandatory '
            f'but, if not, EmptyFlow should be '
            f'considered in extract()'
        )

    def enable(self):
        self._enable = True

    def disable(self):
        self._enable = False

    def name(self) -> str:
        return self.__class__.__name__

    def __str__(self):
        return f'{self.name()}({len(self.featureNames)}): \n' \
               f'    {"; ".join(self.featureNames)}'

    def extract(self, flow: Flow) -> Features:
        raise NotImplementedError


def addFlowStatFeatures(
        d: Features,
        flow: Flow,
        baseName: str,
        pktOperator: Callable[[AbstractPacketBase], Any] = None,
        pktListOperator: Callable[[AbstractPacketList], Collection[Any]] = None,
        defaultValue: float = 0,
) -> Features:
    if pktOperator is not None:
        fwdList = [pktOperator(p) for p in flow.fwdPackets]
        bwdList = [pktOperator(p) for p in flow.bwdPackets]
        pktList = [pktOperator(p) for p in flow.packets]
    elif pktListOperator is not None:
        fwdList = pktListOperator(flow.fwdPackets)
        bwdList = pktListOperator(flow.bwdPackets)
        pktList = pktListOperator(flow.packets)
    else:
        msg = f'pktOperator and pktListOperator ' \
              f'can not be None at the same time'
        logger.error(msg)
        raise ValueError(msg)

    addStatChar2Dict(
        d,
        f'{ForwardFeaturePrefix} {baseName}',
        fwdList,
        defaultValue=defaultValue
    )
    addStatChar2Dict(
        d,
        f'{BackwardFeaturePrefix} {baseName}',
        bwdList,
        defaultValue=defaultValue
    )
    addStatChar2Dict(
        d,
        f'{FlowFeaturePrefix} {baseName}',
        pktList,
        defaultValue=defaultValue
    )
    return d


def addFlowCountSpeedFeatures(
        d: Features,
        flow: Flow,
        baseName: str,
        counter: Callable[[AbstractPacketList], Any],
) -> Features:
    def packetListDuration(pktList: AbstractPacketList):
        duration = 0
        if len(pktList) >= 2:
            duration = pktList[-1].getTs() - pktList[0].getTs()
        return duration

    fwdCount = counter(flow.fwdPackets)
    fwdDuration = packetListDuration(flow.fwdPackets)
    fwdSpeed = 0 if fwdDuration == 0 else fwdCount / fwdDuration
    d[f'{ForwardFeaturePrefix} {baseName} Num'] = fwdCount
    d[f'{ForwardFeaturePrefix} {baseName} Speed'] = fwdSpeed

    bwdCount = counter(flow.bwdPackets)
    bwdDuration = packetListDuration(flow.bwdPackets)
    bwdSpeed = 0 if bwdDuration == 0 else bwdCount / bwdDuration
    d[f'{BackwardFeaturePrefix} {baseName} Num'] = bwdCount
    d[f'{BackwardFeaturePrefix} {baseName} Speed'] = bwdSpeed

    d[f'{RatioFeaturePrefix} {baseName}'] = 0 if bwdCount == 0 else fwdCount / bwdCount

    pktCount = counter(flow.packets)
    pktDuration = packetListDuration(flow.packets)
    pktSpeed = 0 if pktDuration == 0 else pktCount / pktDuration
    d[f'{FlowFeaturePrefix} {baseName} Num'] = pktCount
    d[f'{FlowFeaturePrefix} {baseName} Speed'] = pktSpeed

    return d


class FeatureExtractorManager:
    def __init__(self, *args):
        self._extractors: List[FeatureExtractor] = list()
        for extractor in args:
            if isinstance(extractor, FeatureExtractor):
                self.add(extractor)

    @property
    def allFeatureNames(self) -> List[str]:
        names = list()
        for extractor in self._extractors:
            names.extend(extractor.featureNames)
        return names

    @allFeatureNames.setter
    def allFeatureNames(self, _):
        raise Exception(f'allFeatureNames cannot been set')

    def add(self, extractor: FeatureExtractor):
        if extractor not in self._extractors:
            self._extractors.append(extractor)

    def extend(self, extractors: Iterable[FeatureExtractor]):
        for extractor in extractors:
            self.add(extractor)

    def remove(self, ext: Union[str, FeatureExtractor]):
        extName = ext.name() if isinstance(ext, FeatureExtractor) else ext
        for extractor in self._extractors:
            if extName == extractor.name():
                self._extractors.remove(extractor)
                break

    def clear(self):
        self._extractors.clear()

    def __str__(self):
        retStr = f'Feature Extractors ({len(self._extractors)}):\n' \
                 f'    {", ".join(extractor.name() for extractor in self._extractors)}\n'

        retStr += f'Features ({len(self.allFeatureNames)}):\n' \
                  f'    {", ".join(self.allFeatureNames)}\n'
        summaryList = list()
        for index, extractor in enumerate(self._extractors):
            summaryList.append(f'{index + 1}. {extractor}')
        retStr += '\n'.join(summaryList)
        return retStr

    def extract(self, flow: Flow) -> Features:
        features = dict()
        for extractor in self._extractors:
            features.update(extractor.extract(flow))
        return features


def getBuildInFeatureExtractorManager(activityTimeout=None) -> FeatureExtractorManager:
    from TimeSeriesNetworkFlowMeter.Features.ActiveIdle import ActiveIdle
    from TimeSeriesNetworkFlowMeter.Features.InterArrivalTime import InterArrivalTime
    from TimeSeriesNetworkFlowMeter.Features.PacketCounter import PacketCounter
    from TimeSeriesNetworkFlowMeter.Features.TcpFlagCounter import TcpFlagCounter

    fem = FeatureExtractorManager(
        PacketCounter(),
        TcpFlagCounter(),
        InterArrivalTime(),
        ActiveIdle(activityTimeout),
    )
    logger.info(f'Feature extractors summary:\n{fem}')
    return fem


def getAllBuildInFeatureExtractorManager(activityTimeout=None) -> FeatureExtractorManager:
    from TimeSeriesNetworkFlowMeter.Features.ActiveIdle import ActiveIdle
    from TimeSeriesNetworkFlowMeter.Features.BasicFlowInfo import BasicFlowInfo
    from TimeSeriesNetworkFlowMeter.Features.InterArrivalTime import InterArrivalTime
    from TimeSeriesNetworkFlowMeter.Features.PacketCounter import PacketCounter
    from TimeSeriesNetworkFlowMeter.Features.TcpFlagCounter import TcpFlagCounter

    fem = FeatureExtractorManager(
        BasicFlowInfo(),
        PacketCounter(),
        TcpFlagCounter(),
        InterArrivalTime(),
        ActiveIdle(activityTimeout),
    )
    logger.info(f'All feature extractors (with BasicInfo) summary:\n{fem}')
    return fem
