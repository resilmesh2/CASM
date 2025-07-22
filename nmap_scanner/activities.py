from nmap_scanner.activities_impl import parse_nmap_xml
from nmap_scanner.dtos import NmapConfig, NmapResults
from temporalio import activity


class NmapActivities:
    @activity.defn
    async def parse_nmap_xml(self, config: NmapConfig) -> NmapResults:
        return parse_nmap_xml(config)
