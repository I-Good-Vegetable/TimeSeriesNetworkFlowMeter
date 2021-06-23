from typing import Iterable, Optional, Callable, Any, List, Union, Dict, Type, Tuple

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase, AbstractPacket
from TimeSeriesNetworkFlowMeter.Features.BasicFlowInfo import BasicFlowInfo
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, getAllBuildInFeatureExtractorManager, \
    getBuildInFeatureExtractorManager
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractorManager
from TimeSeriesNetworkFlowMeter.Flow import Flow, FlowTimeout, TimeSeriesFlow, TimeSeriesFlowTimeout, FlowTimeoutBase, \
    FlowBase
from TimeSeriesNetworkFlowMeter.Log import logger
from TimeSeriesNetworkFlowMeter.PCAP import pcap2generator
from TimeSeriesNetworkFlowMeter.Session import FlowSessionManager, checkSessionKeyInfo, pSessionKey
from TimeSeriesNetworkFlowMeter.Typing import FeatureSet, Features, FlowSessionKeyInfo, TimeSeriesFeatureSet, \
    TimeSeriesFeature
from TimeSeriesNetworkFlowMeter.Utils import sortFeatureSet, sortTimeSeriesFeatureSet, featureSet2csv, mkdir, \
    saveTimeSeriesFeatureSet, pBar


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
            # logger.warning(f'A packet has been dropped: {pSessionKey(packet)}')
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


def pcap2csv(
        pcapFile,
        csvFile=None,
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
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
        **kwargs4pcap2generator,
) -> FeatureSet:
    from pathlib import Path
    pcapFile = Path(pcapFile)
    assert pcapFile.exists(), f'{pcapFile} does not exist'
    if csvFile is None:
        csvFile = pcapFile.with_suffix('.csv')
    mkdir(filepath=csvFile)
    featureSet = packets2featureSet(
        pcap2generator(
            str(pcapFile),
            castTo,
            **kwargs4pcap2generator,
        ),
        flowSessionManager,
        flowTimeout,
        flowTimeoutCallback,
        featureExtractors,
        activityTimeout,
        returnSortedFeatureSet,
        sortFeatureAccordingTo,
    )
    featureSet2csv(
        str(csvFile),
        featureSet,
    )
    return featureSet


def pcaps2csvs(
        pcapFolder,
        csvFolder=None,
        recursively=True,
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
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
        **kwargs4pcap2generator,
) -> (Dict[str, FeatureSet], List[str]):
    from pathlib import Path
    pcapFolder = Path(pcapFolder)
    assert pcapFolder.exists(), f'{pcapFolder} does not exist'
    logger.info(f'Enter {pcapFolder}')
    pattern = f'*.[pP][cC][aA][pP]'
    pcapFiles = list(pcapFolder.rglob(pattern)) if recursively \
        else pcapFolder.glob(pattern)
    nPcap = len(pcapFiles)
    logger.info(f'{nPcap} PCAP files are found')

    csvFolder = pcapFolder if csvFolder is None else Path(csvFolder)

    featureSetDict: Dict[str, FeatureSet] = dict()
    failedFiles = list()
    for pcapFile in pcapFiles:
        logger.info(f'Processing {pcapFile}')
        csvFile = (csvFolder / pcapFile.stem).with_suffix('.csv')
        try:
            featureSet = pcap2csv(
                str(pcapFile),
                str(csvFile),
                castTo,
                flowSessionManager,
                flowTimeout,
                flowTimeoutCallback,
                featureExtractors,
                activityTimeout,
                returnSortedFeatureSet,
                sortFeatureAccordingTo,
                **kwargs4pcap2generator,
            )
        except Exception as e:
            failedFiles.append(str(pcapFile))
            logger.error(f'{pcapFile} cannot be processed \n {e}')
        else:
            featureSetDict[str(pcapFile)] = featureSet
            logger.success(f'{pcapFile} has been processed')

    nFailed = len(failedFiles)
    nSucceed = nPcap - nFailed
    logger.info(f'All PCAP files ({nPcap}) in {pcapFolder} have been processed')
    if nSucceed != 0:
        logger.success(f'{nSucceed}/{nPcap} are succeed')
    if nFailed != 0:
        logger.error(f'{nFailed}/{nPcap} are failed')

    return featureSetDict, failedFiles


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


def packets2timeSeriesFeatureSets(
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


def pcap2timeSeriesDataset(
        pcapFile,
        outputFolder=None,
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
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
        defaultValue=0.0,
        indexColName='Index',
        indexFilename='Index.csv',
        featureFilename='Features.npz',
        **kwargs4pcap2generator
) -> TimeSeriesFeatureSet:
    from pathlib import Path
    pcapFile = Path(pcapFile)
    assert pcapFile.exists(), f'{pcapFile} does not exist'
    outputFolder = pcapFile.parent if outputFolder is None \
        else Path(outputFolder)

    tsFeatureSet = packets2timeSeriesFeatureSets(
        pcap2generator(
            str(pcapFile),
            castTo,
            **kwargs4pcap2generator,
        ),
        flowSessionManager,
        timeSeriesFlowTimeout,
        timeSeriesSubFlowLen,
        basicInfoExtractor,
        featureExtractors,
        activityTimeout,
        returnSortedFeatureSet,
        sortFeatureAccordingTo,
    )

    saveTimeSeriesFeatureSet(
        outputFolder,
        tsFeatureSet,
        timeSeriesSubFlowLen,
        defaultValue,
        indexColName,
        indexFilename,
        featureFilename,
    )
    return tsFeatureSet


def pcaps2timeSeriesDatasets(
        pcapFolder,
        outputFolder=None,
        recursively=True,
        outputMode='PcapNameAsPrefix',
        delimiter='_',
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
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
        defaultValue=0.0,
        indexColName='Index',
        indexFilename='Index.csv',
        featureFilename='Features.npz',
        **kwargs4pcap2generator
):
    from pathlib import Path
    pcapFolder = Path(pcapFolder)
    assert pcapFolder.exists(), f'{pcapFolder} does not exist'
    logger.info(f'Enter {pcapFolder}')
    pattern = f'*.[pP][cC][aA][pP]'
    pcapFiles = list(pcapFolder.rglob(pattern)) if recursively \
        else pcapFolder.glob(pattern)
    nPcap = len(pcapFiles)
    logger.info(f'{nPcap} PCAP files are found')
    outputFolder = pcapFolder if outputFolder is None \
        else Path(outputFolder)
    assert outputMode in ['PcapNameAsPrefix', 'IndividualFolders'], \
        f'outputMode incorrect ({outputMode})'

    nFailed = 0
    # for pcapFile in pBar(pcapFiles, description='Converting......'):
    for index, pcapFile in enumerate(pcapFiles):
        logger.info(f'Processing {pcapFile} ({index+1}/{len(pcapFiles)})')
        tmpOutputFolder = outputFolder / pcapFile.stem if outputMode == 'IndividualFolders' \
            else outputFolder
        try:
            pcap2timeSeriesDataset(
                pcapFile,
                tmpOutputFolder,
                castTo,
                flowSessionManager,
                timeSeriesFlowTimeout,
                timeSeriesSubFlowLen,
                basicInfoExtractor,
                featureExtractors,
                activityTimeout,
                returnSortedFeatureSet,
                sortFeatureAccordingTo,
                defaultValue,
                indexColName,
                pcapFile.stem + delimiter + indexFilename
                if outputMode == 'PcapNameAsPrefix' else indexFilename,
                pcapFile.stem + delimiter + featureFilename
                if outputMode == 'PcapNameAsPrefix' else featureFilename,
                **kwargs4pcap2generator,
            )
        except Exception as e:
            nFailed += 1
            logger.error(f'{pcapFile} cannot be processed \n {e}')
        else:
            logger.success(f'{pcapFile} has been processed')

    nSucceed = nPcap - nFailed
    logger.info(f'All PCAP files ({nPcap}) in {pcapFolder} have been processed')
    if nSucceed != 0:
        logger.success(f'{nSucceed}/{nPcap} are succeed')
    if nFailed != 0:
        logger.error(f'{nFailed}/{nPcap} are failed')
