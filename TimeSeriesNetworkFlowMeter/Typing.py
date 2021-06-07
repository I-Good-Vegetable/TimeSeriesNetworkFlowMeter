from typing import Any, List, Dict, Tuple

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase

AbstractPacketList = List[AbstractPacketBase]
PacketSessionKeyInfo = FlowSessionKeyInfo = Tuple[Any, Any, Any, Any, Any]
Features = Dict[str, Any]
FeatureSet = List[Features]
TimeSeriesFeature = Tuple[Features, Dict[int, Features]]
TimeSeriesFeatureSet = List[TimeSeriesFeature]
