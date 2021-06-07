from typing import List

from TimeSeriesNetworkFlowMeter.NetworkBackend import getBackend


class AbstractPacketBase:
    """
    Please avoid using @property and setter,
    in case some subclasses inherit from backend's Packet,
    preventing name collision
    """
    def __init__(self, p):
        self._packet = p

    def __repr__(self):
        return self._packet.__repr__()

    def __str__(self):
        return self._packet.__str__()

    def __contains__(self, item):
        return self._packet.__contains__(item)

    def getProtocol(self):
        """
        Get the highest protocol up to transport layer
        :return: the protocol
        """
        raise NotImplementedError

    def getSrcIp(self):
        raise NotImplementedError

    def getSrcPort(self):
        raise NotImplementedError

    def getDstIp(self):
        raise NotImplementedError

    def getDstPort(self):
        raise NotImplementedError

    def getSrcMac(self):
        raise NotImplementedError

    def getDstMac(self):
        raise NotImplementedError

    def getTs(self):
        """
        Timestamp using second as unit

        :return: timestamp (double)
        """
        raise NotImplementedError

    def getTsDatetime(self):
        from pandas import to_datetime
        return to_datetime(self.getTs(), unit='s')

    def getTsReadable(self, tsFormat=None):
        ts = self.getTsDatetime()
        strTs = str(ts) if tsFormat is None else ts.strftime(tsFormat)
        return strTs

    def getLen(self):
        raise NotImplementedError

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
        raise NotImplementedError


class AbstractPacketPyshark(AbstractPacketBase):

    def getProtocol(self):
        protocol = None
        protocols = {
            # 3rd layer (de facto)
            'TCP': 'TCP',
            'UDP': 'UDP',
            'ICMP': 'ICMP',
            'IGMP': 'IGMP',
            'ICMPV6': 'ICMPv6',
            # 2nd layer
            'IPV6': 'IPv6',
            'IP': 'IP',
            'ARP': 'APR',
            'LLC': 'LLC',
            'LLDP': 'LLDP',
            # 1st layer
            'ETH': 'Ether',
        }
        for p, pName in protocols.items():
            if p in self:
                protocol = pName
                break
        return protocol

    def getSrcIp(self):
        srcIp = None
        if 'IP' in self:
            srcIp = str(self._packet.ip.src)
        elif 'IPV6' in self:
            srcIp = str(self._packet.ipv6.src)
        return srcIp

    def getSrcPort(self):
        srcPort = None
        if 'TCP' in self:
            srcPort = int(self._packet.tcp.srcport)
        elif 'UDP' in self:
            srcPort = int(self._packet.udp.srcport)
        return srcPort

    def getDstIp(self):
        dstIp = None
        if 'IP' in self:
            dstIp = str(self._packet.ip.dst)
        elif 'IPV6' in self:
            dstIp = str(self._packet.ipv6.dst)
        return dstIp

    def getDstPort(self):
        dstPort = None
        if 'TCP' in self:
            dstPort = int(self._packet.tcp.dstport)
        elif 'UDP' in self:
            dstPort = int(self._packet.udp.dstport)
        return dstPort

    def getSrcMac(self):
        srcMac = None
        if 'ETH' in self:
            srcMac = str(self._packet.eth.src)
        return srcMac

    def getDstMac(self):
        dstMac = None
        if 'ETH' in self:
            dstMac = str(self._packet.eth.dst)
        return dstMac

    def getTs(self):
        return float(self._packet.sniff_timestamp)

    def getTsDatetime(self):
        return self._packet.sniff_time

    def getLen(self):
        return int(self._packet.frame_info.len)

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

    def getTcpFlag(self, flagName) -> int:

        if flagName in self._flagExtractors:
            return self._flagExtractors[flagName](self._packet)
        else:
            return 0


class AbstractPacketScapy(AbstractPacketBase):
    def getProtocol(self):
        pass

    def getSrcIp(self):
        pass

    def getSrcPort(self):
        pass

    def getDstIp(self):
        pass

    def getDstPort(self):
        pass

    def getSrcMac(self):
        pass

    def getDstMac(self):
        pass

    def getTs(self):
        pass

    def getLen(self):
        pass

    def getTcpFlag(self, flagName) -> int:
        pass


def AbstractPacket(p) -> AbstractPacketBase:
    return {
        'pyshark': AbstractPacketPyshark,
        'scapy': AbstractPacketScapy,
    }[getBackend()](p)
