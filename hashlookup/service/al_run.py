import functools
import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime

import dns.exception
import dns.rdatatype
import dns.resolver
import redis
import requests
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    JSONSectionBody,
    Result,
    ResultJSONSection,
    ResultMultiSection,
    TextSectionBody,
)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REDIS_SERVER = os.getenv("hashlookup_redis_host", "hashlookup_redis")
REDIS_TTL = 3600 * 24


NX_SENTINEL = "NX"
RETRIES = 2
TIMEOUT = 3

TRUST_SAFE_LEVEL = 80
TRUST_UNSAFE_LEVEL = 20


def create_session(retries, timeout):
    session = requests.Session()

    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.get = functools.partial(session.get, timeout=timeout)

    return session


def retry(exceptions):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(RETRIES):
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    if i == RETRIES - 1:
                        raise

        return wrapper

    return decorator


class CachedLookup(ABC):
    CACHE_TEMPLATE = "hash:{}"

    def __init__(
        self,
        session: requests.Session,
        redis_client: redis.Redis,
        resolver: dns.resolver.Resolver,
        logger: logging.Logger,
    ):
        self._session = session
        self.redis_client = redis_client
        self._resolver = resolver
        self.log = logger

    @abstractmethod
    def _lookup(self, sha1: str) -> dict:
        raise NotImplementedError

    @retry((redis.RedisError, dns.exception.DNSException))
    def lookup_sha1(self, sha1: str):
        response = None
        if cached := self.redis_client.get(self.CACHE_TEMPLATE.format(sha1)):
            response = cached.decode("utf-8")
            return json.loads(response) if response != NX_SENTINEL else None

        try:
            data = self._lookup(sha1)
            self.redis_client.set(self.CACHE_TEMPLATE.format(sha1), json.dumps(data), ex=REDIS_TTL)
            return data
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            response = NX_SENTINEL
            self.redis_client.set(self.CACHE_TEMPLATE.format(sha1), NX_SENTINEL, ex=REDIS_TTL)

        return None


class CIRCLHashlookup(CachedLookup):
    HASHLOOKUP_SERVER = "dns.hashlookup.circl.lu"
    HASHLOOKUP_API = "https://hashlookup.circl.lu/"
    MAX_PARENTS = 10
    CACHE_TEMPLATE = "circl:{}"

    def _get_details(self, sha1: str):
        response = self._session.get(f"{self.HASHLOOKUP_API}/lookup/sha1/{sha1}").json()
        data = {
            "source": response.get("source", ""),
            "name": response.get("FileName", ""),
            "db": response.get("db", ""),
            "trust": response.get("hashlookup:trust", 50),
            "parents": response.get("parents", [])[: self.MAX_PARENTS],
            "product": response.get("ProductCode", {}),
        }
        return data

    def _lookup(self, sha1: str):
        dns_answer = self._resolver.resolve(
            f"{sha1.lower()}.{self.HASHLOOKUP_SERVER}", "TXT", lifetime=TIMEOUT
        )
        dns_answer = dns_answer[0]
        self.log.debug("lookup_sha1(%s) = %s", sha1, dns_answer)
        data = self._get_details(sha1)
        return data


class CymruMalwareHash(CachedLookup):
    HASHLOOKUP_SERVER = "hash.cymru.com"
    CACHE_TEMPLATE = "cymru:{}"

    def _lookup(self, sha1: str):
        dns_answer = self._resolver.resolve(
            f"{sha1.lower()}.{self.HASHLOOKUP_SERVER}", "TXT", lifetime=TIMEOUT
        )
        dns_answer = dns_answer[0].to_text().replace('"', "")
        self.log.debug("lookup_sha1(%s) = %s", sha1, dns_answer)
        timestamp, detection_rate = dns_answer.split(" ")
        data = {
            "last_seen": timestamp,
            "rate": detection_rate,
        }
        return data


class AssemblylineService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self._redis = None

    def _load_config(self):
        self.dns_server = self.config.get("dns_server")
        self.break_on_known = self.config.get("stop_scan_for_well_known", True)
        self.break_deep_scan = self.config.get("stop_deep_scan_for_well_known", False)

        self.use_circl = self.config.get("use_circl_hashlookup", True)
        self.use_cymru = self.config.get("use_cymru_malware_hash", True)

        self.safe_level = self.config.get("safe_level", TRUST_SAFE_LEVEL)
        self.unsafe_level = self.config.get("unsafe_level", TRUST_UNSAFE_LEVEL)

        self._resolver = dns.resolver.Resolver(configure=False if self.dns_server else True)
        if self.dns_server:
            if "," in self.dns_server:
                self._resolver.nameservers = self.dns_server.split(",")
            else:
                self._resolver.nameservers = [self.dns_server]

        self._session = create_session(RETRIES, TIMEOUT)

        self.circl_hashlookup = CIRCLHashlookup(
            self._session, self.redis_client, self._resolver, self.log
        )
        self.cymru_malware_hash = CymruMalwareHash(
            self._session, self.redis_client, self._resolver, self.log
        )

    @property
    def redis_client(self):
        if not self._redis:
            self._redis = redis.Redis(
                host=REDIS_SERVER, port=6379, db=1, socket_connect_timeout=5, socket_timeout=5
            )

        return self._redis

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self._load_config()

        self.log.info(f"{self.service_attributes.name} service started")

    def _check_circl(self, request: ServiceRequest):
        info = self.circl_hashlookup.lookup_sha1(request.sha1)
        if not info:
            return None

        main_section = ResultMultiSection("CIRCL Hashlookup Results")
        description = TextSectionBody()
        description.add_line(f"Known under name: \"{info['name']}\"")
        description.add_line(f"by source {info['source']} {info['db'] if info['db'] else ''}")
        description.add_line(f"Trust level: {info['trust']}")
        description.add_line("")
        description.add_line(
            "Data sourced from CIRCL Hashlookup service, https://www.circl.lu/services/hashlookup/"
        )
        main_section.add_section_part(description)

        if info.get("parents"):
            parents = ResultMultiSection(f"Parents ({len(info['parents'])})", auto_collapse=True)
            main_section.add_subsection(parents)
            for parent in info["parents"]:
                part = JSONSectionBody()
                part.set_json(parent)
                parents.add_section_part(part)

        if info.get("product"):
            product = ResultJSONSection("Product Information")
            product.set_json(info["product"])
            main_section.add_subsection(product)

        if info["trust"] <= self.unsafe_level:
            main_section.set_heuristic(2)
            self._is_malicious = True
        elif info["trust"] >= self.safe_level:
            # Do not try to override malicious results
            main_section.set_heuristic(1 if not self._is_malicious else 3)
            if self.break_on_known and not request.deep_scan:
                request.drop()
            elif self.break_deep_scan and request.deep_scan:
                request.drop()
        return main_section

    def _check_cymru(self, request: ServiceRequest):
        info = self.cymru_malware_hash.lookup_sha1(request.sha1)
        if not info:
            return None

        main_section = ResultMultiSection("Cymru Malware Hash Results")
        description = TextSectionBody()
        description.add_line(
            "This file was found in the Cymru Malware Hash registry (https://www.team-cymru.com/mhr)."
        )
        description.add_line(f"Last seen: {datetime.fromtimestamp(int(info['last_seen']))}")
        description.add_line(f"Detected by {info['rate']}% of the scanners.")

        main_section.add_section_part(description)
        main_section.set_heuristic(2)
        self._is_malicious = True
        return main_section

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()

        self._is_malicious = False

        if self.use_cymru:
            cymru_section = self._check_cymru(request)
            if cymru_section:
                request.result.add_section(cymru_section)

        if self.use_circl:
            circl_section = self._check_circl(request)
            if circl_section:
                request.result.add_section(circl_section)
