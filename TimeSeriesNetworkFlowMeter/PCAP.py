from typing import Union, Callable, Iterable

from pyshark import FileCapture
from scapy.utils import PcapReader

from TimeSeriesNetworkFlowMeter.Log import logger
from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacket, AbstractPacketBase
from TimeSeriesNetworkFlowMeter.NetworkBackend import getBackend
from TimeSeriesNetworkFlowMeter.Typing import AbstractPacketList


def pcap2packets(
        filepath,
        nPackets=-1,
        castTo: Union[
            AbstractPacketBase,
            Callable
        ] = AbstractPacket,
        **kwargs,
) -> AbstractPacketList:
    """
    Load packets from the file and return a list of packets.

    :param filepath: PCAP filepath
    :param nPackets: The number of packets. If -1, return all packets
    :param castTo: Convert the original _packet to
                   a class inherited from AbstractPacketBase
    :param kwargs: The arguments sent to backend PCAP reader
    :return: A list of packets
    """
    logger.info(f'Loading packets from {filepath}')
    return {
        'pyshark': pcap2packetsPyshark,
        'scapy': pcap2packetsScapy,
    }[getBackend()](
        filepath,
        nPackets,
        castTo,
        **kwargs,
    )


def pcap2generator(
        filepath,
        castTo: Union[
            AbstractPacketBase,
            Callable
        ] = AbstractPacket,
        **kwargs,
) -> Iterable[AbstractPacketBase]:
    """
    Load a _packet iterator from the file and return it。

    Since loading the whole PCAP file is the only way to
    obtain the number of packets, if you need the number of
    packets, please refer to pcap2packets

    :param filepath: PCAP filepath
    :param castTo: Convert the original _packet to
                   a class inherited from AbstractPacketBase
    :param kwargs: The arguments sent to FileCapture
    :return: A _packet generator
    """
    logger.info(f'Loading packets from {filepath}')
    return {
        'pyshark': pcap2generatorPyshark,
        'scapy': pcap2generatorScapy,
    }[getBackend()](
        filepath,
        castTo,
        **kwargs,
    )


def pcap2packetsPyshark(
        filepath,
        nPackets=-1,
        castTo: Union[
            AbstractPacketBase,
            Callable
        ] = AbstractPacket,
        **kwargs,
):
    fileCapture = FileCapture(filepath, **kwargs)
    if nPackets == -1:
        packets = [castTo(packet) for packet in fileCapture]
    else:
        packets = [castTo(fileCapture[index]) for index in range(nPackets)]
    fileCapture.close()
    return packets


def pcap2generatorPyshark(
        filepath,
        castTo: Union[
            AbstractPacketBase,
            Callable
        ] = AbstractPacket,
        **kwargs,
):
    fileCapture = FileCapture(filepath, **kwargs)
    iterator = iter(fileCapture)
    while True:
        try:
            packet = next(iterator)
            packet = castTo(packet)
            yield packet
        except StopIteration:
            fileCapture.close()
            break


def pcap2packetsScapy(
        filepath,
        nPackets=-1,
        castTo: Union[
            AbstractPacketBase,
            Callable
        ] = AbstractPacket,
        **kwargs,
):
    reader = PcapReader(filepath, **kwargs)
    packets = []
    while nPackets != 0:
        nPackets -= 1
        try:
            packet = reader.read_packet()
            packet = castTo(packet)
        except EOFError:
            break
        packets.append(packet)
    reader.close()
    return packets


def pcap2generatorScapy(
        filepath,
        castTo: Union[
            AbstractPacketBase,
            Callable
        ] = AbstractPacket,
        **kwargs,
):
    reader = PcapReader(filepath, **kwargs)
    while True:
        try:
            packet = reader.read_packet()
            packet = castTo(packet)
            yield packet
        except EOFError:
            reader.close()
            break
