import csv
import io

from redis import Redis

from config import RedisConfig
from temporalio import activity


class UtilityActivities:
    @activity.defn
    async def get_unique_subdomains(self, *data: str) -> set:
        unique_subdomains = set()
        for item in data:
            unique_subdomains.update(item.splitlines())
        return unique_subdomains

    @activity.defn
    async def csv_to_txt_unique_hosts(self, redis_config: RedisConfig, scan_uuid: str) -> str:
        """
        Extract unique hosts from CSV data in Redis and store them in Redis.
        """
        # Use Redis
        redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)

        # Get CSV data from Redis
        csv_data = redis_client.get(f"passive_output_csv:{scan_uuid}")
        if not csv_data:
            print(f"No CSV data found in Redis for scan_uuid: {scan_uuid}")
            redis_client.close()
            return ""

        # Parse CSV data
        seen = set()
        reader = csv.DictReader(io.StringIO(csv_data.decode('utf-8')))
        for row in reader:
            host = row.get("host", "").strip()
            if host:
                seen.add(host)

        # Store unique hosts in Redis
        unique_hosts = "\n".join(seen)
        redis_client.set(scan_uuid, unique_hosts)
        redis_client.close()

        return scan_uuid
