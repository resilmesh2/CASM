import json

from temporalio import workflow

from nmap_scanner.activities import NmapActivities
from nmap_scanner.dtos import NmapConfig


@workflow.defn
class NmapWorkflow:
    @workflow.run
    async def run(self, config: NmapConfig) -> dict:
        activities = NmapActivities()

        # Parse the Nmap XML file
        results = await workflow.execute_activity(
            activities.parse_nmap_xml,
            config,
            start_to_close_timeout=30
        )

        # Write results to output file
        with open(config.output_file, "w") as f:
            json.dump(results, f, indent=2, default=vars)

        return {
            "message": "Nmap parsing completed successfully",
            "stats": {
                "hosts": len(results.hosts),
                "subnets": len(results.subnets),
                "software_versions": len(results.software_versions),
                "devices": len(results.devices),
                "applications": len(results.applications)
            }
        }