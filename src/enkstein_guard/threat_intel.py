"""Read-only, fixed-destination VirusTotal public-IP reputation connector.

Configure as a trusted tool behind policy controls. It never uploads files/URLs
and returns bounded numeric reputation fields, not arbitrary provider text.
"""
import asyncio
import ipaddress
import json
from urllib.parse import quote
from urllib.request import build_opener, ProxyHandler, HTTPSHandler, Request
from .providers import _NoRedirect
from .runtime import AccessDenied, RejectedBeforeDispatch, UnavailableBeforeDispatch
from .blocking import BoundedBlockingTransport


class VirusTotalIPProvider:
    destination = "www.virustotal.com"
    resource = "ip-reputation"

    def __init__(self, *, broker, credential_name, timeout=15, egress=None, ssl_context=None, max_concurrent_calls=16):
        if type(timeout) not in (int,float) or not 0 < timeout <= 120:
            raise ValueError("invalid_provider_timeout")
        from .egress import opener
        self.broker, self.credential_name = broker, credential_name
        self.timeout = timeout
        self._blocking = BoundedBlockingTransport(max_concurrent_calls)
        self._opener = opener(egress, ssl_context)
        self.egress = egress

    async def call(self, operation):
        if operation.destination != self.destination or operation.resource != self.resource:
            raise RejectedBeforeDispatch("provider_binding_mismatch")
        payload = operation.payload()
        if type(payload) is not dict or set(payload) != {"ip"} or not isinstance(payload["ip"],str):
            raise RejectedBeforeDispatch("invalid_public_ip")
        try:
            address = ipaddress.ip_address(payload["ip"])
            if not address.is_global:
                raise ValueError()
        except ValueError:
            raise RejectedBeforeDispatch("invalid_public_ip") from None
        async def send(credential, ignored_payload):
            return await self._blocking.run(self._request, credential, str(address))
        return await self.broker.invoke(self.credential_name, operation, send)

    def _request(self, credential, address):
        request = Request("https://www.virustotal.com/api/v3/ip_addresses/"+quote(address,safe=""),
                          headers={"x-apikey":credential,"Accept":"application/json"},method="GET")
        try:
            with self._opener.open(request,timeout=self.timeout) as response:
                if response.status != 200:
                    raise ValueError()
                raw=response.read(1_048_577)
                if len(raw)>1_048_576:
                    raise ValueError()
                data=json.loads(raw)["data"]
                if data["type"] != "ip_address" or ipaddress.ip_address(data["id"]) != ipaddress.ip_address(address):
                    raise ValueError()
                attributes=data["attributes"]
                stats=attributes["last_analysis_stats"]
                if type(stats) is not dict or not stats or any(type(v) is not int or not 0<=v<=1_000_000_000 for v in stats.values()):
                    raise ValueError()
                allowed={"harmless","malicious","suspicious","undetected","timeout"}
                if not set(stats)<=allowed:
                    raise ValueError()
                result={"ip":address,"analysis_stats":stats}
                reputation=attributes.get("reputation")
                if reputation is not None:
                    if type(reputation) is not int or not -1_000_000<=reputation<=1_000_000:
                        raise ValueError()
                    result["reputation"]=reputation
                return result
        except Exception as error:
            from .egress import ConnectFailed
            from .providers import failure_code
            if isinstance(error, ConnectFailed):
                raise UnavailableBeforeDispatch(error.code) from None
            failure = AccessDenied("threat_intel_failed")
            failure.reason_code = failure_code(error)
            raise failure from None
