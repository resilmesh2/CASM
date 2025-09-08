import csv
import io
import uuid

from redis import Redis

from config import RedisConfig
from temporalio import activity


class UtilityActivities:
    def __init__(self, redis_config: RedisConfig) -> None:
        self.redis_config = redis_config

    @activity.defn
    async def get_unique_subdomains(self, *data_redis_uuids: str) -> str:
        unique_subdomains = set()
        redis_client = Redis(host=self.redis_config.host, port=self.redis_config.port, db=0)
        for item in data_redis_uuids:
            unique_subdomains.update(redis_client.get(item).splitlines())
        str_unique_subdomains = "\n".join(unique_subdomains)

        unique_subdomains_uuid = f"unique_subdomains-{str(uuid.uuid4())}"
        redis_client.set(unique_subdomains_uuid, str_unique_subdomains)
        redis_client.close()
        return unique_subdomains_uuid

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
            redis_client.close()
            return ""

        # Parse CSV data
        seen = set()
        reader = csv.DictReader(io.StringIO(csv_data.decode("utf-8")))
        for row in reader:
            host = row.get("host", "").strip()
            if host:
                seen.add(host)

        # Store unique hosts in Redis
        unique_hosts = "\n".join(seen)
        redis_client.set(scan_uuid, unique_hosts)
        redis_client.close()

        return scan_uuid
