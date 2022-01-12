import base64
import collections
import functools
import logging
import subprocess
import threading
import time
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

# TODO replace with exponential backoff
PROCESS_PING_ATTEMPTS = 500
PROCESS_PING_INTERVAL = 0.01


def manage_vaultwarden_process(server_ready_event: threading.Event):
    while True:
        logger.info("Starting vaultwarden process")
        with subprocess.Popen(
            args=["vaultwarden"],
            stdin=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        ) as process:
            try:
                for attempt in (x + 1 for x in range(PROCESS_PING_ATTEMPTS)):
                    try:
                        logger.info("Pinging vaultwarden process (attempt %d)", attempt)
                        httpx.get("http://127.0.0.1:8000/alive").raise_for_status()
                        logger.info("Ready to serve requests")
                        server_ready_event.set()
                        break
                    except Exception:
                        time.sleep(PROCESS_PING_INTERVAL)
                else:
                    raise Exception(
                        f"Couldn't ping vaultwarden after {PROCESS_PING_ATTEMPTS} attempts"
                    )
                process.wait()
            except:
                logger.exception(
                    "Exception occurred in process manager, killing vaultwarden"
                )
                process.kill()
            finally:
                logger.error("Process exited with return code %d", process.returncode)
                server_ready_event.clear()


@functools.lru_cache(maxsize=1)
def start_vaultwarden_server() -> threading.Event:
    server_ready_event = threading.Event()
    # since this is a daemon thread, it'll die with the main thread.
    # BUT, vaultwarden won't die since the finally block won't get run,
    # so we're relying on Lambda to kill everything running in the container
    thread = threading.Thread(
        target=manage_vaultwarden_process, args=(server_ready_event,), daemon=True
    )
    thread.start()
    return server_ready_event


def convert_httpx_headers_to_apigw(response):
    # TODO are we handling content-encoding correctly?
    result = collections.defaultdict(list)
    for k, v in response.headers.multi_items():
        if k in {"content-encoding"}:
            continue
        result[k].append(v)
    return result


def convert_apigw_body_to_httpx(event):
    if event["body"] is None:
        return None
    elif event["isBase64Encoded"]:
        return base64.b64decode(event["body"])
    return event["body"].encode("utf-8")


def convert_apigw_headers_to_httpx(event):
    # TODO do we care enough to get multi-value headers working properly?
    headers = {k.lower(): v for k, v in event["headers"].items()}
    headers["x-real-ip"] = event["requestContext"]["identity"]["sourceIp"]
    return headers


def handler(event, _context=None):
    start_vaultwarden_server().wait()  # TODO timeout
    response = httpx.request(
        method=event["httpMethod"],
        url=urllib.parse.urlunsplit(
            (
                "http",
                "127.0.0.1:8000",
                event["path"],
                None,
                None,
            )
        ),
        params=event["multiValueQueryStringParameters"],
        headers=convert_apigw_headers_to_httpx(event),
        content=convert_apigw_body_to_httpx(event),
        follow_redirects=False,
    )
    # TODO allow larger responses by only b64ing when necessary?
    return {
        "statusCode": response.status_code,
        "multiValueHeaders": convert_httpx_headers_to_apigw(response),
        "body": base64.b64encode(response.content).decode("utf-8"),
        "isBase64Encoded": True,
    }
