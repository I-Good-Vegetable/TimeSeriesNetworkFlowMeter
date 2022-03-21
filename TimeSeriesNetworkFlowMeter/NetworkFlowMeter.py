from typing import Iterable, Optional, Callable, Any, List, Union, Dict, Type, Tuple, TypeVar

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase, AbstractPacket
from TimeSeriesNetworkFlowMeter.Features.BasicFlowInfo import BasicFlowInfo
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor, getAllBuildInFeatureExtractorManager, \
    getBuildInFeatureExtractorManager, extractFeatureSetFromFlowPackets
from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractorManager
from TimeSeriesNetworkFlowMeter.Flow import Flow, FlowTimeout, TimeSeriesFlow, TimeSeriesFlowTimeout, FlowTimeoutBase, \
    FlowBase
from TimeSeriesNetworkFlowMeter.Log import logger
from TimeSeriesNetworkFlowMeter.PCAP import pcap2generator
from TimeSeriesNetworkFlowMeter.Session import FlowSessionManager, checkSessionKeyInfo
from TimeSeriesNetworkFlowMeter.Typing import FeatureSet, Features, FlowSessionKeyInfo, TimeSeriesFeatureSet, \
    TimeSeriesFeature, PacketTimeSeriesFeatureSet, PacketTimeSeriesFeature
from TimeSeriesNetworkFlowMeter.Utils import sortFeatureSet, sortTimeSeriesFeatureSetLike, featureSet2csv, mkdir, \
    saveTimeSeriesFeatureSet, findPcapFiles, savePacketTimeSeriesFeatureSet

FlowLike = TypeVar(
    'FlowLike',
    Callable[
        [str, FlowSessionKeyInfo, AbstractPacketBase, Any],
        Any,
    ],
    Type[FlowBase],
)


def logResults(pcapFolder, nPcap=None, nSucceed=None, nFailed=None):
    assert sum([x is None for x in [nPcap, nSucceed, nFailed]]) <= 1
    nPcap = nSucceed + nFailed if nPcap is None else nPcap
    nSucceed = nPcap - nFailed if nSucceed is None else nSucceed
    nFailed = nPcap - nSucceed if nFailed is None else nFailed
    logger.info(f'All PCAP files ({nPcap}) in {pcapFolder} have been processed')
    if nSucceed != 0:
        logger.success(f'{nSucceed}/{nPcap} are succeed')
    if nFailed != 0:
        logger.error(f'{nFailed}/{nPcap} are failed')


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
        FlowType: FlowLike,
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


def pcaps2datasetsGenerator(
        pcapFolder,
        outputFolder=None,
        recursively=True,
        ignoreExceptions=False,
):
    from pathlib import Path
    pcapFiles = findPcapFiles(pcapFolder, recursively)
    nPcap = len(pcapFiles)
    logger.info(f'{nPcap} PCAP files are found')
    outputFolder = pcapFolder if outputFolder is None \
        else Path(outputFolder)

    nSucceed = 0
    for index, pcapFile in enumerate(pcapFiles):
        try:
            logger .info(f'Processing ({index + 1}/{nPcap}): {pcapFile}')
            yield index, pcapFile, outputFolder
        except Exception as e:
            logger.error(f'{pcapFile} cannot be processed \n {e}')
            if not ignoreExceptions:
                raise e
        else:
            nSucceed += 1
            logger.success(f'{pcapFile} has been processed')

    logResults(pcapFolder, nPcap=nPcap, nSucceed=nSucceed)


def flowGenerator(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        FlowType: FlowLike = Flow,
) -> Iterable[FlowLike]:
    for e in flowGeneratorBase(FlowType, packets, flowSessionManager):
        e: FlowTimeout
        flow = e.flow
        yield flow


def packets2flows(
        packets: Iterable[AbstractPacketBase],
        FlowType: FlowLike = Flow,
        flowSessionManager: FlowSessionManager = None,
        flowTimeout=None,
        returnSortedFlows=True,
        flowTimeoutCallback: Optional[Callable[[Flow], Any]] = None
) -> List[Flow]:
    if flowTimeout is not None:
        Flow.setTimeout(flowTimeout)

    flows: List[Flow] = list()
    for flow in flowGenerator(
            packets,
            flowSessionManager,
            FlowType,
    ):
        if flowTimeoutCallback is not None:
            flowTimeoutCallback(flow)
        flows.append(flow)
    if returnSortedFlows:
        flows.sort()
    return flows


def packets2featureSet(
        packets: Iterable[AbstractPacketBase],
        FlowType: FlowLike = Flow,
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
            FlowType,
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
        FlowType: FlowLike = Flow,
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
        FlowType,
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
        outputFolder=None,
        recursively=True,
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
        FlowType: FlowLike = Flow,
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
):
    g = pcaps2datasetsGenerator(pcapFolder, outputFolder, recursively, True)
    for index, pcapFile, outputFolder in g:
        csvFile = (outputFolder / pcapFile.name).with_suffix('.csv')
        try:
            pcap2csv(
                str(pcapFile),
                str(csvFile),
                castTo,
                FlowType,
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
            g.throw(e)


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
        tsFeatureSet = sortTimeSeriesFeatureSetLike(tsFeatureSet, sortFeatureAccordingTo)
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

    logger.info(f'Extracting Time Series Features from {pcapFile}')
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
    logger.success(f'{pcapFile}`s Time Series Features Extracted')

    logger.info(f'Saving Time Series Features to {outputFolder}')
    saveTimeSeriesFeatureSet(
        outputFolder,
        tsFeatureSet,
        timeSeriesSubFlowLen,
        defaultValue,
        indexColName,
        indexFilename,
        featureFilename,
    )
    logger.success(f'Time Series Features Saved to {outputFolder}')
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
    assert outputMode in ['PcapNameAsPrefix', 'IndividualFolders'], \
        f'outputMode incorrect ({outputMode})'

    g = pcaps2datasetsGenerator(pcapFolder, outputFolder, recursively, False)
    for index, pcapFile, outputFolder in g:
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
            g.throw(e)


def packets2packetTimeSeriesFeatureSets(
        packets: Iterable[AbstractPacketBase],
        flowSessionManager: FlowSessionManager = None,
        flowTimeout=None,
        basicInfoExtractor: FeatureExtractor = None,
        returnSorted=True,
        sortAccordingTo='Ts',
) -> PacketTimeSeriesFeatureSet:
    if flowTimeout is not None:
        Flow.setTimeout(flowTimeout)
    if basicInfoExtractor is None:
        basicInfoExtractor = BasicFlowInfo()

    ptsFeatureSet: PacketTimeSeriesFeatureSet = list()
    for flow in flowGenerator(packets, flowSessionManager):
        ptsBasicInfo = basicInfoExtractor.extract(flow)
        packetsFeatureSet = extractFeatureSetFromFlowPackets(flow)
        ptsFeature: PacketTimeSeriesFeature = (
            ptsBasicInfo,
            packetsFeatureSet,
        )
        ptsFeatureSet.append(ptsFeature)
    if returnSorted:
        ptsFeatureSet = sortTimeSeriesFeatureSetLike(
            ptsFeatureSet, sortAccordingTo
        )
    return ptsFeatureSet


def pcap2packetTimeSeriesDataset(
        pcapFile,
        outputFolder=None,
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
        flowSessionManager: FlowSessionManager = None,
        flowTimeout=None,
        basicInfoExtractor: FeatureExtractor = None,
        returnSorted=True,
        sortAccordingTo='Ts',
        indexFilename='Index.csv',
        featureFilename='Features.pkl',
        **kwargs4pcap2generator
):
    from pathlib import Path
    pcapFile = Path(pcapFile)
    assert pcapFile.exists(), f'{pcapFile} does not exist'
    outputFolder = pcapFile.parent if outputFolder is None \
        else Path(outputFolder)

    logger.info(f'Extracting Packet-based Time Series Features from {pcapFile}')
    ptsFeatureSet = packets2packetTimeSeriesFeatureSets(
        pcap2generator(
            str(pcapFile),
            castTo,
            **kwargs4pcap2generator,
        ),
        flowSessionManager,
        flowTimeout,
        basicInfoExtractor,
        returnSorted,
        sortAccordingTo,
    )
    savePacketTimeSeriesFeatureSet(
        outputFolder,
        ptsFeatureSet,
        indexFilename,
        featureFilename
    )


def pcaps2packetTimeSeriesDatasets(
        pcapFolder,
        outputFolder=None,
        recursively=True,
        ignoreExceptions=True,
        outputMode='PcapNameAsPrefix',
        delimiter='_',
        castTo: Union[
            Type[AbstractPacketBase],
            Callable
        ] = AbstractPacket,
        flowSessionManager: FlowSessionManager = None,
        flowTimeout=None,
        basicInfoExtractor: FeatureExtractor = None,
        returnSorted=True,
        sortAccordingTo='Ts',
        indexFilename='Index.csv',
        featureFilename='Features.pkl',
        **kwargs4pcap2generator
):
    assert outputMode in ['PcapNameAsPrefix', 'IndividualFolders'], \
        f'outputMode incorrect ({outputMode})'

    g = pcaps2datasetsGenerator(pcapFolder, outputFolder, recursively, ignoreExceptions)
    for index, pcapFile, outputFolder in g:
        tmpOutputFolder = outputFolder / pcapFile.stem if outputMode == 'IndividualFolders' \
            else outputFolder
        try:
            pcap2packetTimeSeriesDataset(
                pcapFile,
                tmpOutputFolder,
                castTo,
                flowSessionManager,
                flowTimeout,
                basicInfoExtractor,
                returnSorted,
                sortAccordingTo,
                pcapFile.stem + delimiter + indexFilename
                if outputMode == 'PcapNameAsPrefix' else indexFilename,
                pcapFile.stem + delimiter + featureFilename
                if outputMode == 'PcapNameAsPrefix' else featureFilename,
                **kwargs4pcap2generator,
            )
        except Exception as e:
            g.throw(e)
