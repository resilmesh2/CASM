import atexit

from valkey import Valkey

from config import AppConfig, RedisConfig


class RedisHandler:
    def __init__(self, config: RedisConfig) -> None:
        self.client = Valkey(
            host=config.host,
            port=config.port,
            db=config.db,
            decode_responses=True
        )

    def healthcheck(self) -> None:
        pong = self.client.ping()  # pyright: ignore[reportUnknownMemberType]
        if pong is not True:
            raise RuntimeError("Valkey ping failed")

    def close(self) -> None:
        self.client.close()


# Global, per-process singleton
_redis_handler: RedisHandler | None = None


def init_redis() -> RedisHandler:
    global _redis_handler
    if _redis_handler is None:
        config = AppConfig.get().redis
        _redis_handler = RedisHandler(config)
        _redis_handler.healthcheck()
        atexit.register(_redis_handler.close)
    return _redis_handler


def get_redis() -> Valkey:
    handler = init_redis()
    return handler.client
