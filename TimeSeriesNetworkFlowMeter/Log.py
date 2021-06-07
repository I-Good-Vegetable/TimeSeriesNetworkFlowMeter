import sys

# Using Loguru as logging backend
from loguru import logger

from TimeSeriesNetworkFlowMeter.Config import getConfig

DefaultLogTo = getConfig().get('Log', 'to')
DefaultLogLevel = getConfig().get('Log', 'level')
DefaultLogColorize = getConfig().get('Log', 'colorize')


def checkSink(to):
    specialSink = {
        'sys.stdout': sys.stdout,
        'sys.stderr': sys.stderr,
    }
    if to in specialSink:
        sink = specialSink[to]
    else:
        sink = to
    return sink


def checkColorize(c):
    return c == 'True'


def logTo(
        to=None,
        logLevel=None,
        colorize: bool = None
):
    if to is None:
        to = DefaultLogTo
    sink = checkSink(to)

    if logLevel is None:
        logLevel = DefaultLogLevel

    if colorize is None:
        colorize = checkColorize(DefaultLogColorize)

    logger.remove()
    logger.add(
        sink,
        level=logLevel,
        colorize=colorize,
    )

    logger.info(f'Logging to {to}.')
    logger.info(f'Minimum logging level: {logLevel}')


logTo()


def level(name):
    logger.level(name)
    logger.info(f'Change logging level to {name}')
