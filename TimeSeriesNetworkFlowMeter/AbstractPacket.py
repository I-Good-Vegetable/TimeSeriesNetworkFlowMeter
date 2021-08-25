from datetime import datetime
from typing import List

import pytz

from TimeSeriesNetworkFlowMeter.Config import getConfig
from TimeSeriesNetworkFlowMeter.NetworkBackend import getBackend


def checkTimezone(tz):
    return pytz.timezone(tz)


def ts2datetime(ts, tz):
    return datetime.fromtimestamp(ts, tz)


DefaultTimezone = getConfig().get('Packet', 'timezone')
DefaultTimezone = checkTimezone(DefaultTimezone)


class AbstractPacketBase:
    """
    Please avoid using @property and setter,
    in case some subclasses inherit from backend's Packet,
    preventing name collision
    """

    _timezone = DefaultTimezone

    @classmethod
    def getTimezone(cls):
        return cls._timezone

    @classmethod
    def setTimezone(cls, tz: str):
        cls._timezone = checkTimezone(tz)

    def __init__(self, packet):
        self._protocol = self._getProtocol(packet)
        self._srcIp = self._getSrcIp(packet)
        self._srcPort = self._getSrcPort(packet)
        self._dstIp = self._getDstIp(packet)
        self._dstPort = self._getDstPort(packet)
        self._srcMac = self._getSrcMac(packet)
        self._dstMac = self._getDstMac(packet)
        self._ts = self._getTs(packet)
        self._len = self._getLen(packet)
        self._tcpFlags = self._getTcpFlags(packet)

    def __str__(self):
        return '_'.join([
            str(self.getProtocol()),
            str(self.getSrcIp()),
            str(self.getSrcPort()),
            str(self.getDstIp()),
            str(self.getDstPort()),
            str(self.getTs())
        ])

    def _getProtocol(self, packet):  # noqa
        protocol = None
        protocols = {
            # 3rd layer (de facto)
            'TCP': 'TCP',
            'UDP': 'UDP',
            # 'ICMP': 'ICMP',
            # 'IGMP': 'IGMP',
            # 'ICMPV6': 'ICMPv6',

            # 2nd layer
            # 'IPV6': 'IPv6',
            # 'IP': 'IP',
            # 'ARP': 'APR',
            # 'LLC': 'LLC',
            # 'LLDP': 'LLDP',

            # 1st layer
            # 'ETH': 'Ether',
        }
        for p, pName in protocols.items():
            if p in packet:
                protocol = pName
                break
        return protocol

    def getProtocol(self):
        """
        Get the highest protocol up to transport layer
        :return: the protocol
        """
        return self._protocol

    def _getSrcIp(self, packet):
        raise NotImplementedError

    def getSrcIp(self):
        return self._srcIp

    def _getSrcPort(self, packet):
        raise NotImplementedError

    def getSrcPort(self):
        return self._srcPort

    def _getDstIp(self, packet):
        raise NotImplementedError

    def getDstIp(self):
        return self._dstIp

    def _getDstPort(self, packet):
        raise NotImplementedError

    def getDstPort(self):
        return self._dstPort

    def _getSrcMac(self, packet):
        raise NotImplementedError

    def getSrcMac(self):
        return self._srcMac

    def _getDstMac(self, packet):
        raise NotImplementedError

    def getDstMac(self):
        return self._dstMac

    def _getTs(self, packet):
        """
        Timestamp using second as unit

        :return: timestamp (double)
        """
        raise NotImplementedError

    def getTs(self):
        return self._ts

    def getTsDatetime(self):
        return ts2datetime(self.getTs(), self.getTimezone())

    def getTsReadable(self, tsFormat=None):
        ts = self.getTsDatetime()
        strTs = str(ts) if tsFormat is None else ts.strftime(tsFormat)
        return strTs

    def _getLen(self, packet):
        raise NotImplementedError

    def getLen(self):
        return self._len

    def _getTcpFlags(self, packet):
        raise NotImplementedError

    def getTcpFlags(self):
        return self._tcpFlags

    @staticmethod
    def getTcpFlagNames() -> List[str]:
        return [
            'Ack',
            'Cwr',
            'Ecn',
            'Fin',
            'Ns',
            'Push',
            'Res',
            'Reset',
            'Syn',
            'Urg',
        ]

    def getTcpFlag(self, flagName) -> int:
        flag = 0
        if flagName in self._tcpFlags:
            flag = self._tcpFlags[flagName]
        return flag


class AbstractPacketPyshark(AbstractPacketBase):

    def _getSrcIp(self, packet):
        srcIp = None
        if 'IP' in packet:
            srcIp = str(packet.ip.src)
        elif 'IPV6' in packet:
            srcIp = str(packet.ipv6.src)
        return srcIp

    def _getSrcPort(self, packet):
        srcPort = None
        if 'TCP' in packet:
            srcPort = int(packet.tcp.srcport)
        elif 'UDP' in packet:
            srcPort = int(packet.udp.srcport)
        return srcPort

    def _getDstIp(self, packet):
        dstIp = None
        if 'IP' in packet:
            dstIp = str(packet.ip.dst)
        elif 'IPV6' in packet:
            dstIp = str(packet.ipv6.dst)
        return dstIp

    def _getDstPort(self, packet):
        dstPort = None
        if 'TCP' in packet:
            dstPort = int(packet.tcp.dstport)
        elif 'UDP' in packet:
            dstPort = int(packet.udp.dstport)
        return dstPort

    def _getSrcMac(self, packet):
        srcMac = None
        if 'ETH' in packet:
            srcMac = str(packet.eth.src)
        return srcMac

    def _getDstMac(self, packet):
        dstMac = None
        if 'ETH' in packet:
            dstMac = str(packet.eth.dst)
        return dstMac

    def _getTs(self, packet):
        return float(packet.sniff_timestamp)

    def _getLen(self, packet):
        return int(packet.frame_info.len)

    _flagExtractors = {
        'Ack': lambda p: int(p.tcp.flags_ack) if 'TCP' in p else 0,
        'Cwr': lambda p: int(p.tcp.flags_cwr) if 'TCP' in p else 0,
        'Ecn': lambda p: int(p.tcp.flags_ecn) if 'TCP' in p else 0,
        'Fin': lambda p: int(p.tcp.flags_fin) if 'TCP' in p else 0,
        # NS Flag: Experimental, and May Not be Useful
        'Ns': lambda p: int(p.tcp.flags_ns) if 'TCP' in p else 0,
        'Push': lambda p: int(p.tcp.flags_push) if 'TCP' in p else 0,
        'Res': lambda p: int(p.tcp.flags_res) if 'TCP' in p else 0,
        'Reset': lambda p: int(p.tcp.flags_reset) if 'TCP' in p else 0,
        'Syn': lambda p: int(p.tcp.flags_syn) if 'TCP' in p else 0,
        'Urg': lambda p: int(p.tcp.flags_urg) if 'TCP' in p else 0,
    }

    def _getTcpFlags(self, packet):
        return {
            flagName: flagExtractor(packet)
            for flagName, flagExtractor in self._flagExtractors.items()
        }


class AbstractPacketScapy(AbstractPacketBase):

    def _getSrcIp(self, packet):
        sip = None
        if 'IP' in packet:
            sip = packet['IP'].src
        elif 'IPv6' in packet:
            sip = packet['IPv6'].src
        return sip

    def _getSrcPort(self, packet):
        srcPort = None
        if 'TCP' in packet:
            srcPort = packet['TCP'].sport
        elif 'UDP' in packet:
            srcPort = packet['UDP'].sport
        return srcPort

    def _getDstIp(self, packet):
        dip = None
        if 'IP' in packet:
            dip = packet['IP'].dst
        elif 'IPv6' in packet:
            dip = packet['IPv6'].dst
        return dip

    def _getDstPort(self, packet):
        dstPort = None
        if 'TCP' in packet:
            dstPort = packet['TCP'].dport
        elif 'UDP' in packet:
            dstPort = packet['UDP'].dport
        return dstPort

    def _getSrcMac(self, packet):
        srcMac = None
        if hasattr(packet, 'src'):
            srcMac = packet.src
        return srcMac

    def _getDstMac(self, packet):
        dstMac = None
        if hasattr(packet, 'dst'):
            dstMac = packet.dst
        return dstMac

    def _getTs(self, packet):
        return float(packet.time)

    def _getLen(self, packet):
        return len(packet)

    _flagAbbrDict = {
        'Ack': 'A',
        'Cwr': 'C',
        'Ecn': 'E',
        'Fin': 'F',
        # NS Flag: Experimental, and May Not be Useful
        'Ns': 'N',
        'Push': 'P',
        'Res': None,
        'Reset': 'R',
        'Syn': 'S',
        'Urg': 'U',
    }

    def _getTcpFlags(self, packet):
        flags = {
            flagName: int(flagAbbr in packet['TCP'].flags)
            if 'TCP' in packet else 0
            for flagName, flagAbbr in self._flagAbbrDict.items()
        }
        return flags


def AbstractPacket(p) -> AbstractPacketBase:
    return {
        'pyshark': AbstractPacketPyshark,
        'scapy': AbstractPacketScapy,
    }[getBackend()](p)
