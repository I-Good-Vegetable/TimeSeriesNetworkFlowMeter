from math import floor

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase
from TimeSeriesNetworkFlowMeter.Config import getConfig
from TimeSeriesNetworkFlowMeter.Session import Forward, Backward, pDirection, EmptySessionKey, EmptySessionKeyInfo
from TimeSeriesNetworkFlowMeter.Typing import FlowSessionKeyInfo, AbstractPacketList

DefaultFlowTimeout = float(getConfig().get('Flow', 'timeout'))
DefaultSubFlowLen = int(getConfig().get('Flow', 'sub flow len'))


class FlowTimeoutBase(Exception):
    """
    Base class for timeout related issue
    Not an error
    """

    def __init__(self, complete=True):
        self.complete = complete
        message = f'Flow timeout base; ' \
                  f'this is not an error; ' \
                  f'but please remember to catch it'
        super(FlowTimeoutBase, self).__init__(message)


class FlowTimeout(FlowTimeoutBase):
    """
    Raise this exception when flow is timeout
    Not an error
    """

    def __init__(self, flow):
        self.flow: Flow = flow
        super(FlowTimeout, self).__init__()


class TimeSeriesFlowTimeout(FlowTimeoutBase):
    """
    Raise this exception when time series flow is timeout
    Not an error
    """

    def __init__(
            self,
            timeSeriesSubFlow,
            timeSeriesFlow,
            complete,
    ):
        self.timeSeriesSubFlow: TimeSeriesFlow.SubFlow = timeSeriesSubFlow
        self.timeSeriesFlow: TimeSeriesFlow = timeSeriesFlow
        super(TimeSeriesFlowTimeout, self).__init__(complete)


class FlowBase:
    _timeout = None

    @classmethod
    def getTimeout(cls) -> float:
        return float(cls._timeout)

    @classmethod
    def setTimeout(cls, t):
        cls._timeout = float(t)

    def __init__(
            self,
            fsk: str,
            fski: FlowSessionKeyInfo,
            initPacket: AbstractPacketBase = None,
    ):
        self._fsk = fsk
        self._fski = fski

        self._initPacket = self._lastPacket = initPacket

    def empty(self):
        return self._initPacket is None

    def __str__(self):
        readableInfo = f'Protocol: {self.protocol}\n' \
                       f'Src: {self.srcIp}:{self.srcPort}\n' \
                       f'Dst: {self.dstIp}:{self.dstPort}\n' \
                       f'    InitTime: {self.initTsReadable()}\n' \
                       f'    LastTime: {self.lastTsReadable()}'
        return readableInfo

    def __lt__(self, other):
        if not isinstance(other, FlowBase):
            raise TypeError(f'Other should be FlowBase')
        return self.initTs < other.initTs

    def __eq__(self, other):
        if not isinstance(other, FlowBase):
            raise TypeError(f'Other should be FlowBase')
        return self.initTs < other.initTs

    @property
    def sessionKey(self):
        return self._fsk

    @sessionKey.setter
    def sessionKey(self, value):
        raise Exception(f'Cannot set session key '
                        f'once the flow is initialized')

    @property
    def initTs(self):
        if self._initPacket is None:
            raise Exception(f'Flow\'s first packet is None')
        return self._initPacket.getTs()

    @initTs.setter
    def initTs(self, ts):
        raise Exception(f'Cannot set initTs')

    @property
    def initTsDatetime(self):
        if self._initPacket is None:
            raise Exception(f'Flow\'s first packet is None')
        return self._initPacket.getTsDatetime()

    @initTsDatetime.setter
    def initTsDatetime(self, datetime):
        raise Exception(f'Cannot set initTsDatetime')

    def initTsReadable(self, tsFormat=None):
        if self._initPacket is None:
            raise Exception(f'Flow\'s first packet is None')
        return self._initPacket.getTsReadable(tsFormat)

    @property
    def lastTs(self):
        if self._lastPacket is None:
            raise Exception(f'Flow\'s last packet is None')
        return self._lastPacket.getTs()

    @lastTs.setter
    def lastTs(self, ts):
        raise Exception(f'Cannot set initTs')

    @property
    def lastTsDatetime(self):
        if self._lastPacket is None:
            raise Exception(f'Flow\'s last packet is None')
        return self._lastPacket.getTsDatetime()

    @lastTsDatetime.setter
    def lastTsDatetime(self, datetime):
        raise Exception(f'Cannot set initTsDatetime')

    def lastTsReadable(self, tsFormat=None):
        if self._lastPacket is None:
            raise Exception(f'Flow\'s last packet is None')
        return self._lastPacket.getTsReadable(tsFormat)

    @property
    def duration(self):
        return self.lastTs - self.initTs

    @duration.setter
    def duration(self, d):
        raise Exception(f'Cannot set duration')

    @property
    def protocol(self):
        p = None
        if self._fski is not None:
            p, _, _, _, _ = self._fski
        return p

    @protocol.setter
    def protocol(self, p):
        raise Exception(f'Cannot set protocol')

    @property
    def srcIp(self):
        sip = None
        if self._fski is not None:
            _, sip, _, _, _ = self._fski
        return sip

    @srcIp.setter
    def srcIp(self, sip):
        raise Exception(f'Cannot set src ip')

    @property
    def srcPort(self):
        sport = None
        if self._fski is not None:
            _, _, sport, _, _ = self._fski
        return sport

    @srcPort.setter
    def srcPort(self, sport):
        raise Exception(f'Cannot set src port')

    @property
    def dstIp(self):
        dip = None
        if self._fski is not None:
            _, _, _, dip, _ = self._fski
        return dip

    @dstIp.setter
    def dstIp(self, dip):
        raise Exception(f'Cannot set dst ip')

    @property
    def dstPort(self):
        dport = None
        if self._fski is not None:
            _, _, _, _, dport = self._fski
        return dport

    @dstPort.setter
    def dstPort(self, dport):
        raise Exception(f'Cannot set dst port')

    def isTimeout(
            self,
            packet: AbstractPacketBase,
    ):
        packetTs = packet.getTs()
        if packetTs - self.initTs > self.getTimeout():
            return True
        else:
            return False

    def raiseTimeoutException(self):
        """
        Force flow to construct timeout exception
        """
        raise NotImplementedError

    def add(
            self,
            packet: AbstractPacketBase,
            direction=None,
    ):
        """
        Add a packet to the flow;
        if timeout, FlowTimeout exception will be raised

        :param packet: The packet
        :param direction: The direction
        :raise FlowTimeoutBase
        """
        raise NotImplementedError


class Flow(FlowBase):
    _timeout = DefaultFlowTimeout

    def __init__(
            self,
            fsk: str,
            fski: FlowSessionKeyInfo,
            initPacket: AbstractPacketBase = None,
            initPacketDirection=None,
    ):
        super(Flow, self).__init__(
            fsk,
            fski,
            initPacket,
        )
        self._fwdPackets: AbstractPacketList = list()
        self._bwdPackets: AbstractPacketList = list()
        self._packets: AbstractPacketList = list()
        if initPacket is not None:
            self._appendPacketToLists(
                initPacket,
                pDirection(initPacket, fsk)
                if initPacketDirection is None
                else initPacketDirection
            )

    def __len__(self):
        return len(self.packets)

    @property
    def fwdPackets(self):
        return self._fwdPackets

    @fwdPackets.setter
    def fwdPackets(self, _):
        raise Exception(f'Cannot set fwdPackets')

    @property
    def bwdPackets(self):
        return self._bwdPackets

    @bwdPackets.setter
    def bwdPackets(self, value):
        raise Exception(f'Cannot set bwdPackets')

    @property
    def packets(self):
        return self._packets

    @packets.setter
    def packets(self, value):
        raise Exception(f'Cannot set packets')

    def _appendPacketToLists(
            self,
            packet: AbstractPacketBase,
            direction,
    ):
        """
        Append a packet to forward, backward, and packet lists

        :param packet: The packet
        :param direction: The packet's direction
        """
        self._packets.append(packet)
        if direction == Forward:
            self._fwdPackets.append(packet)
        elif direction == Backward:
            self._bwdPackets.append(packet)
        else:
            raise ValueError(f'Direction can only be {Forward} or '
                             f'{Backward}; {direction} is not available')

    def raiseTimeoutException(self):
        raise FlowTimeout(self)

    def add(self, packet: AbstractPacketBase, direction=None):
        direction = pDirection(packet, self._fsk) if direction is None else direction
        if self.empty():
            self._initPacket = self._lastPacket = packet

        if self.isTimeout(packet):
            raise FlowTimeout(self)

        self._lastPacket = packet
        self._appendPacketToLists(packet, direction)


def _generateTimeout(flowTimeout, subFlowLen):
    return flowTimeout / subFlowLen


class TimeSeriesFlow(FlowBase):
    class SubFlow(Flow):
        _timeout = _generateTimeout(
            DefaultFlowTimeout,
            DefaultSubFlowLen,
        )

        @classmethod
        def setTimeout(cls, t):
            raise Exception(f'Please do not set SubFlow\'s timeout; '
                            f'instead, please invoke TimeSeriesFlow\'s '
                            f'setTimeout and setSubFlowLen')

        _index = None

        @property
        def index(self):
            return self._index

        @index.setter
        def index(self, value):
            raise Exception(f'Cannot set index')

        def __init__(
                self,
                fsk: str,
                fski: FlowSessionKeyInfo,
                initPacket: AbstractPacketBase = None,
                initPacketDirection=None,
                index=None,
        ):
            super(TimeSeriesFlow.SubFlow, self).__init__(
                fsk,
                fski,
                initPacket,
                initPacketDirection,
            )
            self._index = index

    _timeout = DefaultFlowTimeout
    _subFlowLen = DefaultSubFlowLen

    @classmethod
    def _updateSubFlowTimeout(cls):
        subFlowTimeout = _generateTimeout(
            cls.getTimeout(),
            cls.getSubFlowLen(),
        )
        cls.SubFlow._timeout = subFlowTimeout

    @classmethod
    def setTimeout(cls, t):
        """
        Override setTimeout to update sub flow timeout

        :param t: timeout
        """
        super(TimeSeriesFlow, cls).setTimeout(t)
        cls._updateSubFlowTimeout()

    @classmethod
    def getSubFlowLen(cls):
        return int(cls._subFlowLen)

    @classmethod
    def setSubFlowLen(cls, value):
        cls._subFlowLen = int(value)
        cls._updateSubFlowTimeout()

    def __init__(
            self,
            fsk: str,
            fski: FlowSessionKeyInfo,
            initPacket: AbstractPacketBase,
            initPacketDirection,
    ):
        super(TimeSeriesFlow, self).__init__(
            fsk,
            fski,
            initPacket,
        )
        self._tmpIndex = self.generateSubFlowIndex(initPacket)
        self._tmpSubFlow = self.SubFlow(
            fsk,
            fski,
            initPacket,
            initPacketDirection,
            self._tmpIndex,
        )
        self._subFlows = dict()

    def generateSubFlowIndex(self, packet: AbstractPacketBase) -> int:
        index = (packet.getTs() - self.initTs) / self.SubFlow.getTimeout()
        return floor(index)

    @property
    def subFlows(self):
        return self._subFlows

    @subFlows.setter
    def subFlows(self, _):
        raise Exception(f'Cannot set subFlows')

    def raiseTimeoutException(self):
        self._subFlows[self._tmpIndex] = self._tmpSubFlow
        raise TimeSeriesFlowTimeout(self._tmpSubFlow, self, True)

    def add(self, packet: AbstractPacketBase, direction=None):

        if self.isTimeout(packet):
            self._subFlows[self._tmpIndex] = self._tmpSubFlow
            raise TimeSeriesFlowTimeout(self._tmpSubFlow, self, True)

        self._lastPacket = packet

        subFlowIndex = self.generateSubFlowIndex(packet)
        if subFlowIndex == self._tmpIndex:
            self._tmpSubFlow.add(packet, direction)
        elif subFlowIndex > self._tmpIndex:
            oldSubFlow = self._tmpSubFlow
            self._subFlows[self._tmpIndex] = oldSubFlow
            self._tmpSubFlow = self.SubFlow(
                self._fsk,
                self._fski,
                packet,
                direction,
                subFlowIndex,
            )
            self._tmpIndex = subFlowIndex
            raise TimeSeriesFlowTimeout(oldSubFlow, self, False)
        else:
            raise ValueError(f'Please notice the packet\'s order. '
                             f'Index ({subFlowIndex}) is negative')


# The Empty Flow is used for Feature Extractors
EmptyFlow = Flow(EmptySessionKey, EmptySessionKeyInfo)
