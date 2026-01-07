import datetime
from dataclasses import dataclass, field


@dataclass
class HopData:
    prev_ip: str
    hops: int
    next_ip: str | None


@dataclass
class ConnectionData:
    dst_ip: str | None
    hops: list[HopData] = field(default_factory=list[HopData])


@dataclass
class ScanResult:
    data: list[ConnectionData] = field(default_factory=list[ConnectionData])
    time: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat())
