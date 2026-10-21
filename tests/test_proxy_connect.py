import json
import os
import re
import sys
from pathlib import Path
from subprocess import PIPE, Popen
from urllib.parse import urlsplit, urlunsplit

import pytest
from testfixtures import LogCapture
from twisted.internet.defer import inlineCallbacks

from scrapy.http import Request
from scrapy.utils.test import get_crawler
from tests.mockserver.http import MockServer
from tests.spiders import SimpleSpider, SingleRequestSpider


class MitmProxy:
    auth_user = "scrapy"
    auth_pass = "scrapy"

    def start(self):
        script = """
import sys
from mitmproxy.tools.main import mitmdump
sys.argv[0] = "mitmdump"
sys.exit(mitmdump())
        """
        cert_path = Path(__file__).parent.resolve() / "keys"
        import subprocess
        # Start mitmdump and capture both stdout and stderr
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-u",
                "-c",
                script,
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                "0",
                "--proxyauth",
                f"{self.auth_user}:{self.auth_pass}",
                "--set",
                f"confdir={cert_path}",
                "--ssl-insecure",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        # Read output until we find the listening address or timeout
        import time
        host_port = None
        deadline = time.time() + 5.0
        buf = []
        while time.time() < deadline:
            out = self.proc.stdout.readline()
            if not out:
                time.sleep(0.01)
                continue
            line = out.decode("utf-8", errors="replace")
            buf.append(line)
            m = re.search(r"listening at (?:http://)?([^:]+:\d+)", line)
            if m:
                host_port = m.group(1)
                break
        if not host_port:
            # try remaining output
            try:
                remaining = self.proc.stdout.read() or b""
                remaining_decoded = remaining.decode("utf-8", errors="replace")
            except Exception:
                remaining_decoded = ""
            buf.append(remaining_decoded)
            m = re.search(r"listening at (?:http://)?([^:]+:\d+)", "".join(buf))
            if m:
                host_port = m.group(1)
        if not host_port:
            try:
                self.proc.kill()
            except Exception:
                pass
            raise RuntimeError("Could not determine mitmdump listening address from output")
        return f"http://{self.auth_user}:{self.auth_pass}@{host_port}"

    def stop(self):
        self.proc.kill()
        self.proc.communicate()


def _wrong_credentials(proxy_url):
    bad_auth_proxy = list(urlsplit(proxy_url))
    bad_auth_proxy[1] = bad_auth_proxy[1].replace("scrapy:scrapy@", "wrong:wronger@")
    return urlunsplit(bad_auth_proxy)


class TestProxyConnect:
    @classmethod
    def setup_class(cls):
        cls.mockserver = MockServer()
        cls.mockserver.__enter__()

    @classmethod
    def teardown_class(cls):
        cls.mockserver.__exit__(None, None, None)

    def setup_method(self):
        try:
            import mitmproxy  # noqa: F401,PLC0415
        except ImportError:
            pytest.skip("mitmproxy is not installed")

        self._oldenv = os.environ.copy()

        self._proxy = MitmProxy()
        proxy_url = self._proxy.start()
        os.environ["https_proxy"] = proxy_url
        os.environ["http_proxy"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["HTTP_PROXY"] = proxy_url

    def teardown_method(self):
        self._proxy.stop()
        # Restore environment without rebinding os.environ to a plain dict
        os.environ.clear()
        os.environ.update(self._oldenv)

    @inlineCallbacks
    def test_https_connect_tunnel(self):
        crawler = get_crawler(SimpleSpider)
        with LogCapture() as log:
            yield crawler.crawl(self.mockserver.url("/status?n=200", is_secure=True))
        self._assert_got_response_code(200, log)

    @inlineCallbacks
    def test_https_tunnel_auth_error(self):
        os.environ["https_proxy"] = _wrong_credentials(os.environ["https_proxy"])
        crawler = get_crawler(SimpleSpider)
        with LogCapture() as log:
            yield crawler.crawl(self.mockserver.url("/status?n=200", is_secure=True))
        # The proxy returns a 407 error code but it does not reach the client;
        # he just sees a TunnelError.
        self._assert_got_tunnel_error(log)

    @inlineCallbacks
    def test_https_tunnel_without_leak_proxy_authorization_header(self):
        request = Request(self.mockserver.url("/echo", is_secure=True))
        crawler = get_crawler(SingleRequestSpider)
        with LogCapture() as log:
            yield crawler.crawl(seed=request)
        self._assert_got_response_code(200, log)
        echo = json.loads(crawler.spider.meta["responses"][0].text)
        assert "Proxy-Authorization" not in echo["headers"]

    def _assert_got_response_code(self, code, log):
        assert str(log).count(f"Crawled ({code})") == 1

    def _assert_got_tunnel_error(self, log):
        assert "TunnelError" in str(log)
