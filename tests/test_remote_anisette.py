"""Tests for RemoteAnisetteProvider header passthrough and GSA/2FA handling."""

# ruff: noqa: SLF001

from __future__ import annotations

import asyncio
import base64
import plistlib
from unittest.mock import AsyncMock, MagicMock, patch

from findmy.reports.account import AsyncAppleAccount, _normalize_2fa_status
from findmy.reports.anisette import RemoteAnisetteProvider

MAC_ANI_RESPONSE = {
    "X-Apple-I-Client-Time": "2026-11-26T07:03:59Z",
    "X-Apple-I-MD": "AAAABQAAABC/FuQmblq9GXUeHtggIbUaAAAAAQ==",
    "X-Apple-I-MD-LU": "NDlBMkZDQzctOTI0NS01MjNGLThGRTEtMTVEMTMxMjkxOTM0",
    "X-Apple-I-MD-M": (
        "rnQ0W9mpRONTfcDGr74EmShLmbBhMj8uyfCMxmETl/VLfwzuBhe0/q17LqPfCvEHyULI6DD1alXPvjkI"
    ),
    "X-Apple-I-MD-RINFO": "33883392",
    "X-Apple-I-SRL-NO": "0",
    "X-Apple-I-TimeZone": "GMT",
    "X-Apple-Locale": "en_US",
    "X-MMe-Client-Info": (
        "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    ),
    "X-Mme-Device-Id": "49A2FCC7-9245-523F-8FE1-15D131291934",
}


def test_remote_anisette_preserves_server_identity() -> None:
    """RemoteAnisetteProvider preserves RINFO, LU, Device-Id, and Client-Info from server."""
    prov = RemoteAnisetteProvider("https://example.invalid")
    fake_resp = MagicMock()
    fake_resp.json.return_value = MAC_ANI_RESPONSE
    prov._http.get = AsyncMock(return_value=fake_resp)

    headers = asyncio.run(prov.get_headers("local-uid", "local-devid", with_client_info=True))

    assert headers["X-Apple-I-MD"] == MAC_ANI_RESPONSE["X-Apple-I-MD"]
    assert headers["X-Apple-I-MD-M"] == MAC_ANI_RESPONSE["X-Apple-I-MD-M"]
    assert headers["X-Apple-I-MD-RINFO"] == "33883392"
    assert headers["X-Apple-I-MD-LU"] == MAC_ANI_RESPONSE["X-Apple-I-MD-LU"]
    assert headers["X-Mme-Device-Id"] == "49A2FCC7-9245-523F-8FE1-15D131291934"
    assert headers["X-Apple-I-Client-Time"] == "2026-11-26T07:03:59Z"
    assert headers["X-Apple-I-TimeZone"] == "GMT"
    assert headers["X-Apple-Locale"] == "en_US"
    assert headers["loc"] == "en_US"
    assert headers["X-Mme-Client-Info"] == (
        "<MacBookPro13,3> <Mac OS X;10.12.6;16G29>"
        " <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
    )
    assert prov.client == MAC_ANI_RESPONSE["X-MMe-Client-Info"]
    assert prov.get_client_info("com.apple.AOSKit/282 (com.apple.accountsd/113)") == (
        "<MacBookPro13,3> <Mac OS X;10.12.6;16G29>"
        " <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
    )


def test_remote_anisette_falls_back_when_minimal_response() -> None:
    """Servers returning only X-Apple-I-MD and X-Apple-I-MD-M keep default fallbacks."""
    prov = RemoteAnisetteProvider("https://example.invalid")
    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "X-Apple-I-MD": "otp-val",
        "X-Apple-I-MD-M": "mid-val",
    }
    prov._http.get = AsyncMock(return_value=fake_resp)

    headers = asyncio.run(prov.get_headers("uid-1", "dev-1"))

    assert headers["X-Apple-I-MD"] == "otp-val"
    assert headers["X-Apple-I-MD-M"] == "mid-val"
    assert headers["X-Apple-I-MD-RINFO"] == "17106176"
    assert headers["X-Apple-I-MD-LU"] == base64.b64encode(b"uid-1").decode()
    assert headers["X-Mme-Device-Id"] == "DEV-1"


def test_gsa_request_syncs_uid_and_devid_and_uses_server_client_info() -> None:
    """_gsa_request syncs uid/devid from remote Anisette and sends matching X-MMe-Client-Info."""
    prov = RemoteAnisetteProvider("https://example.invalid")
    fake_ani_resp = MagicMock()
    fake_ani_resp.json.return_value = MAC_ANI_RESPONSE
    prov._http.get = AsyncMock(return_value=fake_ani_resp)

    acc = AsyncAppleAccount(anisette=prov)
    captured: dict[str, object] = {}

    async def fake_post(url: str, *, headers: dict[str, str], data: bytes) -> MagicMock:
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = plistlib.loads(data)
        resp = MagicMock()
        resp.ok = True
        resp.plist.return_value = {"Response": {"Status": {"ec": 0}}}
        return resp

    acc._http.post = fake_post  # type: ignore[method-assign]
    asyncio.run(acc._gsa_request({"o": "init"}))

    assert acc._uid == "49A2FCC7-9245-523F-8FE1-15D131291934"
    assert acc._devid == "49a2fcc7-9245-523f-8fe1-15d131291934"
    assert (
        captured["headers"]["X-MMe-Client-Info"]  # type: ignore[index]
        == MAC_ANI_RESPONSE["X-MMe-Client-Info"]
    )
    cpd = captured["body"]["Request"]["cpd"]  # type: ignore[index]
    assert cpd["X-Apple-I-MD-RINFO"] == "33883392"
    assert cpd["X-Apple-I-MD-LU"] == MAC_ANI_RESPONSE["X-Apple-I-MD-LU"]
    assert cpd["X-Mme-Device-Id"] == "49A2FCC7-9245-523F-8FE1-15D131291934"


def test_gsa_request_tolerates_non_base64_hex_lu() -> None:
    """Hex X-Apple-I-MD-LU from dadoum/anisette-v3-server does not crash _gsa_request."""
    prov = RemoteAnisetteProvider("https://example.invalid")
    fake_ani_resp = MagicMock()
    fake_ani_resp.json.return_value = {
        **MAC_ANI_RESPONSE,
        "X-Apple-I-MD-LU": "4AFCD7BAA77F16F06B05897EE7CC36F98AC65DB31E09BAA02273FDA6717F7ACC",
    }
    prov._http.get = AsyncMock(return_value=fake_ani_resp)

    acc = AsyncAppleAccount(anisette=prov)
    orig_uid = acc._uid

    async def fake_post(
        _url: str,
        *,
        headers: dict[str, str],  # noqa: ARG001
        data: bytes,  # noqa: ARG001
    ) -> MagicMock:
        resp = MagicMock()
        resp.ok = True
        resp.plist.return_value = {"Response": {"Status": {"ec": 0}}}
        return resp

    acc._http.post = fake_post  # type: ignore[method-assign]
    asyncio.run(acc._gsa_request({"o": "init"}))

    assert acc._uid == orig_uid


def test_normalize_2fa_status() -> None:
    """hsc=409 without au is normalized to trustedDeviceSecondaryAuth."""
    st = {"hsc": 409, "ec": 0}
    _normalize_2fa_status(st)
    assert st["au"] == "trustedDeviceSecondaryAuth"

    st_existing = {"hsc": 409, "au": "secondaryAuth"}
    _normalize_2fa_status(st_existing)
    assert st_existing["au"] == "secondaryAuth"

    st_ok = {"hsc": 200, "ec": 0}
    _normalize_2fa_status(st_ok)
    assert "au" not in st_ok


def test_remote_anisette_cache_aligns_to_30s_otp_boundary() -> None:
    """Cached remote Anisette data expires at the next 30-second CoreADI OTP boundary."""
    prov = RemoteAnisetteProvider("https://example.invalid")
    fake_resp = MagicMock()
    fake_resp.json.return_value = MAC_ANI_RESPONSE
    prov._http.get = AsyncMock(return_value=fake_resp)

    with patch("findmy.reports.anisette.time.time", return_value=1_700_000_008.0):
        asyncio.run(prov.get_headers("u", "d"))
        assert prov._http.get.await_count == 1
        assert prov._anisette_data_expires_at == 1_700_000_010.0

    # Still inside the same 30-second window (1700000009 < 1700000010): uses cache
    with patch("findmy.reports.anisette.time.time", return_value=1_700_000_009.5):
        asyncio.run(prov.get_headers("u", "d"))
        assert prov._http.get.await_count == 1

    # Crossed into the next 30-second window (1700000010): refetches fresh OTP
    with patch("findmy.reports.anisette.time.time", return_value=1_700_000_010.1):
        asyncio.run(prov.get_headers("u", "d"))
        assert prov._http.get.await_count == 2
        assert prov._anisette_data_expires_at == 1_700_000_040.0
