import os

import py

import TimeSeriesNetworkFlowMeter


CONFIG_PATH = os.path.join(os.path.dirname(TimeSeriesNetworkFlowMeter.__file__), 'Config.ini')


_config = py.iniconfig.IniConfig(CONFIG_PATH)
print(f'Config has been loaded')


def getConfig():
    return _config
