"""
Since we may use different tools (e.g., pyshark and scapy) as backends to analyze packets and PCAP,
a backend manager is necessary.
"""

from contextlib import contextmanager

from TimeSeriesNetworkFlowMeter.Config import getConfig
from TimeSeriesNetworkFlowMeter.Log import logger

DefaultBackend: str = getConfig().get('Backend', 'backend')
logger.info(f'Using {DefaultBackend} as default network backend')

supportedBackend = ['pyshark', 'scapy']


class NetworkBackend:
    _backend = DefaultBackend

    @staticmethod
    def get():
        return NetworkBackend._backend

    @staticmethod
    def set(b):
        if b in supportedBackend:
            logger.info(f'Change network backend from '
                        f'{NetworkBackend._backend} to {b}')
            NetworkBackend._backend = b
        else:
            raise ValueError(f'{b} is not supported as a backend')


def getBackend():
    return NetworkBackend.get()


def setBackend(b):
    NetworkBackend.set(b)


@contextmanager
def backend(b=DefaultBackend):
    """
    An easier way to temporary determine the backend

    :param b: The backend
    """
    tmpBackend = NetworkBackend.get()
    NetworkBackend.set(b)
    yield
    NetworkBackend.set(tmpBackend)
