from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase
from TimeSeriesNetworkFlowMeter.Config import getConfig
from TimeSeriesNetworkFlowMeter.Typing import PacketSessionKeyInfo, FlowSessionKeyInfo
from TimeSeriesNetworkFlowMeter.Utils import returnArray

DefaultDelimiter: str = getConfig().get('Session', 'delimiter')
Forward = getConfig().get('Session', 'forward')
Backward = getConfig().get('Session', 'backward')
Bidirectional = getConfig().get('Session', 'bidirectional')
Unidirectional = getConfig().get('Session', 'unidirectional')
EmptySessionKey = str(None)
EmptySessionKeyInfo = (None, None, None, None, None)


def pSessionKeyInfo(packet: AbstractPacketBase) -> PacketSessionKeyInfo:
    """
    Session Key Info of a _packet: protocol, srcIp, srcPort, dstIp, dstPort

    :param packet: the _packet
    :return: protocol, srcIp, srcPort, dstIp, dstPort
    """
    return (
        packet.getProtocol(),
        packet.getSrcIp(),
        packet.getSrcPort(),
        packet.getDstIp(),
        packet.getDstPort(),
    )


def pSessionKey(
        packet: AbstractPacketBase,
        delimiter: str = DefaultDelimiter
) -> str:
    """
    A string version of the _packet's session key information

    :param packet: The _packet
    :param delimiter: Delimiter which combines the session key info
    :return: A string of session key info
    """
    return delimiter.join([str(info) for info in pSessionKeyInfo(packet)])


def pSessionKeyInfoReverse(packet: AbstractPacketBase):
    """
    Reverse Session Key Info of a _packet: protocol, srcIp, srcPort, dstIp, dstPort

    :param packet: the _packet
    :return: protocol, dstIp, dstPort, srcIp, srcPort
    """
    return (
        packet.getProtocol(),
        packet.getDstIp(),
        packet.getDstPort(),
        packet.getSrcIp(),
        packet.getSrcPort(),
    )


def pSessionKeyReverse(
        packet: AbstractPacketBase,
        delimiter: str = DefaultDelimiter
):
    """
    A string version of the _packet's reverse session key information

    :param packet: The _packet
    :param delimiter: Delimiter which combines the session key info
    :return: A string of session key info
    """
    return delimiter.join([str(info) for info in pSessionKeyInfoReverse(packet)])


def pDirection(
        packet: AbstractPacketBase,
        fsk,
):
    """
    Get packet direction according to FSK

    :param packet: The packet
    :param fsk: The flow session key
    :return: direction
    """
    return Forward if pSessionKey(packet) == fsk else Backward


def checkSessionKey(sk: str):
    return not sk.startswith(f'{None}')


def checkSessionKeyInfo(ski):
    p, _, _, _, _ = ski
    return p is not None


class FlowSessionManager:
    _supportedDirection = [Bidirectional, Unidirectional]

    def __init__(
            self,
            direction=Bidirectional
    ):
        """
        Initiate a flow session manager, which takes
        the first unseen packet direction as forward
        direction.

        If Unidirectional is specified, any packet's
        direction will be forward.

        :param direction: Unidirectional or Bidirectional
        """
        if direction not in self._supportedDirection:
            raise ValueError(f'Unsupported direction: {direction}')
        self._direction = direction
        # _sessions: {packet session key: (flow session key, direction)}
        self._sessions = dict()
        # key and key info map: {packet session key: packet session key info}
        self._keyInfoMap = dict()

    @property
    def direction(self):
        return self._direction

    @direction.setter
    def direction(self, _):
        raise Exception(f'Cannot set direction')

    def _addNewFlowSessionKey(
            self,
            packet: AbstractPacketBase,
    ):
        psk = pSessionKey(packet)
        if self._direction == Bidirectional:
            self._sessions[psk] = (psk, Forward)
            self._keyInfoMap[psk] = pSessionKeyInfo(packet)
            pskReverse = pSessionKeyReverse(packet)
            if pskReverse != psk:
                self._sessions[pskReverse] = (psk, Backward)
                self._keyInfoMap[pskReverse] = pSessionKeyInfoReverse(packet)
        elif self._direction == Unidirectional:
            self._sessions[psk] = (psk, Forward)
            self._keyInfoMap[psk] = pSessionKeyInfo(packet)
        else:
            raise ValueError(f'Unsupported direction: {self._direction}')

    def fSessionKey(
            self,
            packet: AbstractPacketBase,
            returnFski=True,
            returnDirection=True,
    ):
        psk = pSessionKey(packet)
        if psk not in self._sessions:
            self._addNewFlowSessionKey(packet)
        fsk, direction = self._sessions[psk]
        retVals = [fsk]
        if returnFski:
            retVals.append(self._keyInfoMap[fsk])
        if returnDirection:
            retVals.append(direction)
        return returnArray(retVals)

    def fsk2fski(
            self,
            fsk,
    ) -> FlowSessionKeyInfo:
        """
        Obtain Flow Session Key Info (FSKI) according to Flow Session Key (FSK)

        :param fsk: The FSK
        :return: The FSKI
        """
        fski = None
        if fsk in self._keyInfoMap:
            fski = self._keyInfoMap[fsk]
        return fski
