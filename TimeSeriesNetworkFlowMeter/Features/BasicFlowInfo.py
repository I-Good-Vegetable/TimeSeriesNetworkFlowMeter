from TimeSeriesNetworkFlowMeter.Features.Feature import FeatureExtractor
from TimeSeriesNetworkFlowMeter.Flow import FlowBase
from TimeSeriesNetworkFlowMeter.Typing import Features
from TimeSeriesNetworkFlowMeter.Utils import s2us


class BasicFlowInfo(FeatureExtractor):
    """
    Extract Basic Flow Information, e.g., session key, ip, port, ts
    """

    def extract(self, flow: FlowBase) -> Features:
        features = {
            'Session Key': flow.sessionKey,
            'Protocol': flow.protocol,
            'Src IP': flow.srcIp,
            'Src Port': flow.srcPort,
            'Dst IP': flow.dstIp,
            'Dst Port': flow.dstPort,
            'Init Ts': None if flow.empty() else flow.initTsReadable(),
            'Last Ts': None if flow.empty() else flow.lastTsReadable(),
            'Ts': None if flow.empty() else flow.initTs,
            'Duration': None if flow.empty() else s2us(flow.duration),
            # 'Src Mac': set(),
            # 'Dst Mac': set(),

            # This Label is only a Placeholder
            # It can be manually labeled or create another feature extractor to generate labels
            'Label': '',
        }

        # if not flow.empty():
        #     for p in flow.packets:
        #         features['Src Mac'].add(p.getSrcMac())
        #         features['Dst Mac'].add(p.getDstMac())
        # features['Src Mac'] = '; '.join(str(mac) for mac in features['Src Mac'])
        # features['Dst Mac'] = '; '.join(str(mac) for mac in features['Dst Mac'])
        return features
