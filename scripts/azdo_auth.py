"""Microsoft sign-in for Azure DevOps -- no PAT required.

Uses the Azure CLI public client id with the Azure DevOps resource scope, the
same pair the Azure DevOps Copilot plugin uses. Tokens are cached locally so a
browser sign-in is only needed once per refresh-token lifetime. The dashboard
prefers Azure CLI's Windows broker/browser login when the CLI is installed.

Import get_access_token() from other scripts, or run this file to sign in.
"""

import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

AUTHORITY = "https://login.microsoftonline.com/common/oauth2/v2.0"
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI public client
DEVOPS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"
SCOPE = "{}/.default offline_access openid profile".format(DEVOPS_RESOURCE)

CACHE_PATH = os.environ.get(
    "AZDO_TOKEN_CACHE",
    # Per-user, outside the tool directory, so a shared copy of this script
    # never carries one person's tokens to another machine.
    os.path.join(os.path.expanduser("~"), ".azdo_cli_token.json"),
)

_login_lock = threading.Lock()
_cli_login = None


def _azure_cli():
    path = shutil.which("az")
    if path:
        return path
    if sys.platform == "win32":
        for base in ("ProgramFiles", "ProgramFiles(x86)"):
            path = os.path.join(os.environ.get(base, ""),
                                "Microsoft SDKs", "Azure", "CLI2", "wbin", "az.cmd")
            if os.path.isfile(path):
                return path
    return ""


def _run_cli(args, timeout=60, interactive=False):
    exe = _azure_cli()
    if not exe:
        raise RuntimeError("Azure CLI is not installed. Install Microsoft.AzureCLI "
                           "or use an authentication method approved by IT.")
    env = os.environ.copy()
    env["AZURE_CORE_LOGIN_EXPERIENCE_V2"] = "off"
    if sys.platform == "win32":
        env["AZURE_CORE_ENABLE_BROKER_ON_WINDOWS"] = "true"
    flags = 0
    if sys.platform == "win32":
        flags = (subprocess.CREATE_NEW_CONSOLE if interactive
                 else subprocess.CREATE_NO_WINDOW)
    try:
        result = subprocess.run(
            [exe] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            encoding="utf-8", errors="replace", timeout=timeout,
            env=env, creationflags=flags)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Azure CLI sign-in timed out. Try again.")
    except OSError as exc:
        raise RuntimeError("Could not run Azure CLI: {}".format(exc))
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or
                           "Azure CLI failed with exit code {}.".format(result.returncode))
    return result.stdout


def _cli_token():
    output = _run_cli(["account", "get-access-token", "--resource",
                       DEVOPS_RESOURCE, "--output", "json"])
    try:
        token = json.loads(output)
        access_token = token["accessToken"]
        expires_in = float(token["expires_on"]) - time.time()
        if not isinstance(access_token, str) or not access_token or expires_in <= 60:
            raise ValueError("Missing or expired token.")
    except (ValueError, KeyError, TypeError):
        raise RuntimeError("Azure CLI returned an invalid or expired Azure DevOps token.")
    return _write_cache({"access_token": access_token, "expires_in": expires_in,
                         "provider": "azure_cli"})


def begin_signin():
    """Prefer Windows broker/browser login when Azure CLI is installed."""
    global _cli_login
    if not _azure_cli():
        return begin_device_code()
    with _login_lock:
        if _cli_login and _cli_login["status"] == "pending":
            raise RuntimeError("A Windows sign-in is already running. "
                               "Complete it before starting another.")
        login_id = secrets.token_urlsafe(24)
        _cli_login = {"id": login_id, "status": "pending", "error": ""}
    threading.Thread(target=_finish_cli_signin, args=(login_id,), daemon=True).start()
    return {"mode": "azure_cli", "loginId": login_id, "interval": 2, "expiresIn": 420}


def _finish_cli_signin(login_id):
    error = ""
    try:
        _run_cli(["login", "--allow-no-subscriptions", "--output", "none"],
                 timeout=300, interactive=True)
        _cli_token()
    except (RuntimeError, OSError) as exc:
        error = str(exc)
    with _login_lock:
        if _cli_login and _cli_login["id"] == login_id:
            _cli_login.update(status="error" if error else "ok", error=error)


def poll_signin(payload):
    login_id = payload.get("loginId")
    if login_id:
        with _login_lock:
            if not _cli_login or _cli_login["id"] != login_id:
                raise RuntimeError("Unknown or expired Windows sign-in.")
            if _cli_login["status"] == "error":
                raise RuntimeError(_cli_login["error"])
            return _cli_login["status"]
    code = payload.get("deviceCode")
    if not code:
        raise RuntimeError("Missing sign-in identifier.")
    return poll_device_code(code)


def _post(url, fields):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return None, json.loads(body)
        except ValueError:
            return None, {"error": "http_{}".format(exc.code), "error_description": body}
    except urllib.error.URLError as exc:
        raise SystemExit("Network error contacting Microsoft identity: {}".format(exc.reason))


def _read_cache():
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (IOError, OSError, ValueError):
        return {}


def _write_cache(payload):
    cache = {
        "access_token": payload.get("access_token", ""),
        "refresh_token": payload.get("refresh_token", ""),
        # Renew a minute early so a token cannot expire mid-request.
        "expires_at": time.time() + max(0, int(payload.get("expires_in", 0)) - 60),
    }
    if payload.get("provider") == "azure_cli":
        cache["provider"] = "azure_cli"
    with open(CACHE_PATH, "w", encoding="utf-8") as handle:
        json.dump(cache, handle)
    try:
        os.chmod(CACHE_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return cache


def _device_code_flow():
    start, err = _post(AUTHORITY + "/devicecode",
                       {"client_id": CLIENT_ID, "scope": SCOPE})
    if err:
        raise SystemExit("Could not start sign-in: {}".format(
            err.get("error_description", err)))

    print("\n" + "=" * 68)
    print("  Open:  {}".format(start.get("verification_uri")))
    print("  Code:  {}".format(start.get("user_code")))
    print("=" * 68)
    print("Sign in with your NI account. Waiting...\n")
    sys.stdout.flush()

    interval = int(start.get("interval", 5))
    deadline = time.time() + int(start.get("expires_in", 900))
    while time.time() < deadline:
        time.sleep(interval)
        token, err = _post(AUTHORITY + "/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": start["device_code"],
        })
        if token:
            print("Signed in.\n")
            return _write_cache(token)
        code = (err or {}).get("error", "")
        if code == "authorization_pending":
            continue
        if code == "slow_down":
            interval += 5
            continue
        raise SystemExit("Sign-in failed: {}".format(
            err.get("error_description", code)))
    raise SystemExit("Sign-in timed out.")


def get_access_token(force_login=False):
    """Return a valid Azure DevOps access token, signing in only when needed."""
    cache = {} if force_login else _read_cache()
    if cache.get("access_token") and cache.get("expires_at", 0) > time.time():
        return cache["access_token"]
    if cache.get("provider") == "azure_cli":
        try:
            return _cli_token()["access_token"]
        except RuntimeError as exc:
            raise SystemExit("Windows sign-in required: {}".format(exc))
    if cache.get("refresh_token"):
        token, err = _post(AUTHORITY + "/token", {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": cache["refresh_token"],
            "scope": SCOPE,
        })
        if token:
            return _write_cache(token)["access_token"]
    if _azure_cli() and not force_login:
        raise SystemExit("Sign in through the dashboard's Windows sign-in button.")
    return _device_code_flow()["access_token"]


def have_credentials():
    """True when a cached token exists that may still be usable."""
    cache = _read_cache()
    return bool(cache.get("access_token") or cache.get("refresh_token")
                or cache.get("provider") == "azure_cli")


def is_signed_in():
    """True when a token can be obtained without a new browser sign-in."""
    cache = _read_cache()
    if cache.get("access_token") and cache.get("expires_at", 0) > time.time():
        return True
    if cache.get("provider") == "azure_cli":
        try:
            _cli_token()
            return True
        except RuntimeError:
            return False
    if not cache.get("refresh_token"):
        return False
    token, _ = _post(AUTHORITY + "/token", {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": cache["refresh_token"],
        "scope": SCOPE,
    })
    if token:
        _write_cache(token)
        return True
    return False


def begin_device_code():
    """Start a device code sign-in without blocking. Used by the dashboard so
    a user never has to touch the command line."""
    start, err = _post(AUTHORITY + "/devicecode",
                       {"client_id": CLIENT_ID, "scope": SCOPE})
    if err:
        raise RuntimeError(err.get("error_description") or err.get("error")
                           or "Could not start sign-in.")
    return {
        "deviceCode": start["device_code"],
        "userCode": start.get("user_code", ""),
        "url": start.get("verification_uri", "https://microsoft.com/devicelogin"),
        "interval": int(start.get("interval", 5)),
        "expiresIn": int(start.get("expires_in", 900)),
    }


def poll_device_code(device_code):
    """One non-blocking poll. Returns 'pending', 'slow_down' or 'ok'."""
    token, err = _post(AUTHORITY + "/token", {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code,
    })
    if token:
        _write_cache(token)
        return "ok"
    code = (err or {}).get("error", "")
    if code in ("authorization_pending", "slow_down"):
        return code
    raise RuntimeError((err or {}).get("error_description") or code
                       or "Sign-in failed.")


def sign_out():
    try:
        os.remove(CACHE_PATH)
        print("Signed out; cached tokens removed.")
    except OSError:
        print("No cached tokens to remove.")


if __name__ == "__main__":
    if "--sign-out" in sys.argv:
        sign_out()
    else:
        get_access_token(force_login="--force" in sys.argv)
        print("Access token cached at {}".format(CACHE_PATH))
