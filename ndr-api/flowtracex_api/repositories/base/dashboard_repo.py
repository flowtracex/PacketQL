from abc import ABC, abstractmethod

class DashboardRepository(ABC):
    @abstractmethod
    def get_overview_metrics(self):
        """Returns { critical_alerts: {...}, high_alerts: {...}, assets_monitored: {...}, network_health: {...} }"""
        pass

    @abstractmethod
    def get_traffic_metrics(self, range_str):
        """Returns { dataPoints: [{ timestamp, trafficMBps, alerts }] }"""
        pass

    @abstractmethod
    def get_protocol_distribution(self):
        """Returns { protocols: [{ name, percentage, volume, anomaly, source }] }"""
        pass

    @abstractmethod
    def get_deep_inspection_coverage(self):
        """Returns { zeek_coverage, flow_coverage, hybrid_coverage }"""
        pass
