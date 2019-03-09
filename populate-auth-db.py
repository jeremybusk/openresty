#!/usr/bin/env python3
# Simple redis keystore with sha256 hashed http auth string that comes after Authorization: in header
# apt-get install -y python3-redis
import redis
from base64 import b64encode
from hashlib import sha256
username='exampleuser'
password='examplepass'
rdb = redis.Redis(host='localhost', port=6379, db=0)
authorization_string = 'Basic ' + b64encode(f'{username}:{password}'.encode('utf-8')).decode("ascii")
http_authorization_sha256 = sha256(authorization_string.encode('utf-8')).hexdigest()
rdb.hset(username, 'http_authorization_sha256', http_authorization_sha256 )
res = rdb.hgetall(username)
print(res)
