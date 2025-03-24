import os
import redis
from config import Config

class RedisManager:
    def __init__(self):
        self.redis_client = redis.from_url(os.getenv('REDIS_URL'))

    def add_to_whitelist(self, user_id, refresh_token, exp):
        try:
            self.redis_client.set(f"whitelist:{user_id}", refresh_token, ex=exp)
        except Exception as e:
            print(e)

    def is_in_whitelist(self, user_id, refresh_token):
        try:
            stored_token = self.redis_client.get(f"whitelist:{user_id}")
            return stored_token and stored_token.decode('utf-8') == refresh_token
        except Exception as e:
            print(e)

    def remove_from_whitelist(self, user_id):
        self.redis_client.delete(f"whitelist:{user_id}")

    def add_to_blacklist(self, jti, exp):
        self.redis_client.set(f"blacklist:{jti}", "revoked", ex=exp)

    def is_in_blacklist(self, jti):
        return self.redis_client.exists(f"blacklist:{jti}")

redis_client = RedisManager()