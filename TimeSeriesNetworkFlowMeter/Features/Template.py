from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor
from TimeSeriesNetworkFlowMeter.Flow import Flow
from TimeSeriesNetworkFlowMeter.Typing import Features


class FeatureExtractorTemplate(FeatureExtractor):

    def extract(self, flow: Flow) -> Features:
        pass
