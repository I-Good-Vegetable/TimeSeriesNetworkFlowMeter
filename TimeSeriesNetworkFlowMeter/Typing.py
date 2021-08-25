from typing import Any, List, Dict, Tuple

from TimeSeriesNetworkFlowMeter.AbstractPacket import AbstractPacketBase

AbstractPacketList = List[AbstractPacketBase]
PacketSessionKeyInfo = FlowSessionKeyInfo = Tuple[Any, Any, Any, Any, Any]
Features = Dict[str, Any]
FeatureSet = List[Features]
TimeSeriesFeatureLike = Tuple[Features, Any]
TimeSeriesFeatureSetLike = List[TimeSeriesFeatureLike]
TimeSeriesFeature = Tuple[Features, Dict[int, Features]]
TimeSeriesFeatureSet = List[TimeSeriesFeature]
PacketTimeSeriesFeature = Tuple[Features, FeatureSet]
PacketTimeSeriesFeatureSet = List[PacketTimeSeriesFeature]
