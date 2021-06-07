from typing import Iterable, Optional, Callable, Any, List, Union, Dict, Type, Tuple

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase
from TimeSeriesNetworkFlowMeter.Features.BasicFlowInfo import BasicFlowInfo
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, getAllBuildInFeatureExtractorManager, \
    getBuildInFeatureExtractorManager
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractorManager
from TimeSeriesNetworkFlowMeter.Flow import Flow, FlowTimeout, TimeSeriesFlow, TimeSeriesFlowTimeout, FlowTimeoutBase, \
    FlowBase
from TimeSeriesNetworkFlowMeter.Log import logger
from TimeSeriesNetworkFlowMeter.Session import FlowSessionManager, checkSessionKeyInfo
from TimeSeriesNetworkFlowMeter.Typing import FeatureSet, Features, FlowSessionKeyInfo, TimeSeriesFeatureSet, \
    TimeSeriesFeature
from TimeSeriesNetworkFlowMeter.Utils import sortFeatureSet, sortTimeSeriesFeatureSet


def checkFeatureExtractorManager(
        featureExtractors: Union[
            FeatureExtractor,
            Iterable[FeatureExtractor],
            FeatureExtractorManager,
        ] = None,
        getDefaultFeatureExtractorManager: Callable[
            [Any], FeatureExtractorManager,
        ] = None,
        *args,
        **kwargs,
) -> FeatureExtractorManager:
    if isinstance(featureExtractors, FeatureExtractorManager):
        fem = featureExtractors
    elif isinstance(featureExtractors, FeatureExtractor):
        fem = FeatureExtractorManager(featureExtractors)
    elif isinstance(featureExtractors, Iterable):
        fem = FeatureExtractorManager(*featureExtractors)
    else:
        if getDefaultFeatureExtractorManager is None:
            getDefaultFeatureExtractorManager = getAllBuildInFeatureExtractorManager
        fem = getDefaultFeatureExtractorManager(*args, **kwargs)
    return fem


def flowGeneratorBase(
        FlowType: Union[
            Type[Flow],
            Type[TimeSeriesFlow],
            Callable[[
                         str, FlowSessionKeyInfo, AbstractPacketBase, Any
                     ], Any],
            Type[FlowBase],
        ],
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
):
    fsm = FlowSessionManager() if flowSessionManager is None \
        else flowSessionManager
    totalPackets = droppedPackets = 0
    aliveFlows: Dict[FlowType] = dict()
    for packet in packets:
        totalPackets += 1
        fsk, fski, direction = fsm.fSessionKey(
            packet=packet,
            returnFski=True,
            returnDirection=True,
        )
        if not checkSessionKeyInfo(fski):
            droppedPackets += 1
            logger.warning(f'A packet has been dropped:\n{packet}')
            continue
        if fsk in aliveFlows:
            try:
                aliveFlows[fsk].add(packet, direction)
            except FlowTimeoutBase as e:
                yield e
                if e.complete:
                    aliveFlows[fsk] = FlowType(fsk, fski, packet, direction)
        else:
            aliveFlows[fsk] = FlowType(fsk, fski, packet, direction)
    # Flush alive flows
    for flow in aliveFlows.values():
        try:
            flow.raiseTimeoutException()
        except FlowTimeoutBase as e:
            yield e

    acceptedPackets = totalPackets - droppedPackets
    logger.info(f'Total packets: {totalPackets}')
    logger.success(f'Accepted packets: '
                   f'{acceptedPackets}/{totalPackets} '
                   f'({acceptedPackets / totalPackets:.2%})')
    if droppedPackets != 0:
        logger.warning(f'Dropped packet: '
                       f'{droppedPackets}/{totalPackets} '
                       f'({droppedPackets / totalPackets:.2%})')


def flowGenerator(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
) -> Iterable[Flow]:
    for e in flowGeneratorBase(Flow, packets, flowSessionManager):
        e: FlowTimeout
        flow = e.flow
        yield flow


def packets2flows(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        flowTimeout=None,
        returnSortedFlows=True,
        flowTimeoutCallback: Optional[Callable[[Flow], Any]] = None
) -> List[Flow]:
    if flowTimeout is not None:
        Flow.setTimeout(flowTimeout)

    flows = list()
    for flow in flowGenerator(
            packets,
            flowSessionManager,
    ):
        if flowTimeoutCallback is not None:
            flowTimeoutCallback(flow)
        flows.append(flow)
    if returnSortedFlows:
        flows.sort()
    return flows


def packets2featureSet(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        flowTimeout=None,
        flowTimeoutCallback: Callable[[Features], Any] = None,
        featureExtractors: Union[
            FeatureExtractor,
            Iterable[FeatureExtractor],
            FeatureExtractorManager,
        ] = None,
        activityTimeout=None,
        returnSortedFeatureSet=True,
        sortFeatureAccordingTo='Ts',
) -> FeatureSet:
    if flowTimeout is not None:
        Flow.setTimeout(flowTimeout)
    fem = checkFeatureExtractorManager(
        featureExtractors,
        getAllBuildInFeatureExtractorManager,
        activityTimeout=activityTimeout,
    )
    featureSet: FeatureSet = list()
    for flow in flowGenerator(
            packets,
            flowSessionManager,
    ):
        features = fem.extract(flow)
        if flowTimeoutCallback is not None:
            flowTimeoutCallback(features)
        featureSet.append(features)
    if returnSortedFeatureSet:
        featureSet = sortFeatureSet(featureSet, sortFeatureAccordingTo)
    return featureSet


def timeSeriesFlowGenerator(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        enableSubFlow=True,
) -> Tuple[TimeSeriesFlow.SubFlow, TimeSeriesFlow, bool]:
    for e in flowGeneratorBase(
            TimeSeriesFlow,
            packets,
            flowSessionManager
    ):
        e: TimeSeriesFlowTimeout
        subFlow = e.timeSeriesSubFlow
        flow = e.timeSeriesFlow
        complete = e.complete
        if enableSubFlow:
            yield subFlow, flow, complete
        elif complete:
            yield None, flow, complete


def packets2timeSeriesFlows(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        timeSeriesFlowTimeout=None,
        timeSeriesSubFlowTimeout=None,
        returnSortedTimeSeriesFlows=True,
        timeSeriesFlowTimeoutCallback: Callable[
            [TimeSeriesFlow], Any
        ] = None,
        timeSeriesSubFlowTimeoutCallback: Callable[
            [TimeSeriesFlow.SubFlow, TimeSeriesFlow, bool], Any
        ] = None,
) -> List[TimeSeriesFlow]:
    if timeSeriesFlowTimeout is not None:
        TimeSeriesFlow.setTimeout(timeSeriesFlowTimeout)
    if timeSeriesSubFlowTimeout is not None:
        TimeSeriesFlow.SubFlow.setTimeout(timeSeriesSubFlowTimeout)

    timeSeriesFlows: List[TimeSeriesFlow] = list()
    for subFlow, flow, complete in timeSeriesFlowGenerator(
        packets,
        flowSessionManager,
        timeSeriesSubFlowTimeoutCallback is not None
    ):
        if timeSeriesSubFlowTimeoutCallback is not None:
            timeSeriesSubFlowTimeoutCallback(subFlow, flow, complete)
        if complete:
            if timeSeriesFlowTimeoutCallback is not None:
                timeSeriesFlowTimeoutCallback(flow)
            timeSeriesFlows.append(flow)
    if returnSortedTimeSeriesFlows:
        timeSeriesFlows.sort()
    return timeSeriesFlows


def packet2timeSeriesFeatureSets(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        timeSeriesFlowTimeout=None,
        timeSeriesSubFlowLen=None,
        basicInfoExtractor: FeatureExtractor = None,
        featureExtractors: Union[
            FeatureExtractor,
            Iterable[FeatureExtractor],
            FeatureExtractorManager,
        ] = None,
        activityTimeout=None,
        returnSortedFeatureSet=True,
        sortFeatureAccordingTo='Ts',
) -> TimeSeriesFeatureSet:
    if timeSeriesFlowTimeout is not None:
        TimeSeriesFlow.setTimeout(timeSeriesFlowTimeout)
    if timeSeriesSubFlowLen is not None:
        TimeSeriesFlow.setSubFlowLen(timeSeriesSubFlowLen)
    if basicInfoExtractor is None:
        basicInfoExtractor = BasicFlowInfo()
    fem = checkFeatureExtractorManager(
        featureExtractors,
        getBuildInFeatureExtractorManager,
        activityTimeout=activityTimeout,
    )

    tsFeatureSet: TimeSeriesFeatureSet = list()
    for _, flow, complete in timeSeriesFlowGenerator(
        packets,
        flowSessionManager,
        False,
    ):
        # only consider the completed situation
        tsBasicInfo = basicInfoExtractor.extract(flow)
        sfFeatureSets = {
            index: fem.extract(subFlow)
            for index, subFlow in flow.subFlows.items()
        }
        tsFeature: TimeSeriesFeature = (
            tsBasicInfo,
            sfFeatureSets,
        )
        tsFeatureSet.append(tsFeature)
    if returnSortedFeatureSet:
        tsFeatureSet = sortTimeSeriesFeatureSet(
            tsFeatureSet,
            sortFeatureAccordingTo,
        )
    return tsFeatureSet
