import os

import py

import TimeSeriesNetworkFlowMeter

CONFIG_PATH = os.path.join(os.path.dirname(TimeSeriesNetworkFlowMeter.__file__), 'Config.ini')


def getConfig():
    return py.iniconfig.IniConfig(CONFIG_PATH)
