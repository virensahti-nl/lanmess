import json
import time

from lanmess_files.config import DISCOVERY_TTL
from lanmess_files.discovery import Discovery, _Protocol


def _packet(name="bob", port=50510, code_tag="abc"):
    return {
        "app": "lanmess",
        "version": 4,
        "name": name,
        "tcp_port": port,
        "code_tag": code_tag,
        "ed_pub": "aa" * 32,
        "x25519_pub": "bb" * 32,
    }


def _feed(discovery, packet, ip="10.0.0.5"):
    proto = _Protocol(discovery._on_packet)
    payload = json.dumps(packet).encode("utf-8")
    proto.datagram_received(payload, (ip, 12345))


def test_accepts_valid_packet():
    d = Discovery()
    _feed(d, _packet())
    assert "bob" in d.peers
    assert d.peers["bob"]["ip"] == "10.0.0.5"
    assert d.peers["bob"]["tcp_port"] == 50510
    assert d.peers["bob"]["code_tag"] == "abc"


def test_rejects_wrong_app():
    d = Discovery()
    p = _packet()
    p["app"] = "other"
    _feed(d, p)
    assert d.peers == {}


def test_rejects_missing_app_field():
    d = Discovery()
    p = _packet()
    p.pop("app", None)
    _feed(d, p)
    assert d.peers == {}


def test_rejects_missing_name():
    d = Discovery()
    p = _packet()
    p["name"] = ""
    _feed(d, p)
    _feed(d, {"app": "lanmess", "tcp_port": 50510})
    assert d.peers == {}


def test_rejects_bad_port():
    d = Discovery()
    for bad in (0, -1, 65536, "50510", None, 50510.5):
        p = _packet()
        p["tcp_port"] = bad
        _feed(d, p)
    assert d.peers == {}


def test_rejects_malformed_json():
    d = Discovery()
    proto = _Protocol(d._on_packet)
    proto.datagram_received(b"not json", ("10.0.0.5", 12345))
    assert d.peers == {}


def test_rejects_non_dict_packet():
    d = Discovery()
    proto = _Protocol(d._on_packet)
    proto.datagram_received(b"[1, 2, 3]", ("10.0.0.5", 12345))
    assert d.peers == {}


def test_rejects_oversize_datagram():
    d = Discovery()
    proto = _Protocol(d._on_packet)
    proto.datagram_received(b"x" * (65536 + 100), ("10.0.0.5", 12345))
    assert d.peers == {}


def test_ttl_expires_entry():
    d = Discovery()
    _feed(d, _packet())
    assert "bob" in d.get_live_peers()
    d.peers["bob"]["last_seen"] = time.time() - (DISCOVERY_TTL + 10)
    assert "bob" not in d.get_live_peers()


def test_find_by_code_tag():
    d = Discovery()
    _feed(d, _packet("bob", 50510, "abc"), "10.0.0.5")
    _feed(d, _packet("alice", 50511, "def"), "10.0.0.6")
    name, info = d.find_by_code_tag("abc")
    assert name == "bob"
    name, info = d.find_by_code_tag("def")
    assert name == "alice"


def test_find_by_code_tag_no_match():
    d = Discovery()
    _feed(d, _packet("bob", 50510, "abc"))
    name, info = d.find_by_code_tag("xyz")
    assert name is None
    assert info is None


def test_find_by_code_tag_exclude():
    d = Discovery()
    _feed(d, _packet("bob", 50510, "abc"))
    name, info = d.find_by_code_tag("abc", exclude_name="bob")
    assert name is None


def test_find_by_name():
    d = Discovery()
    _feed(d, _packet("bob"))
    assert d.find_by_name("bob") is not None
    assert d.find_by_name("nobody") is None


def test_replaces_stale_entry():
    d = Discovery()
    _feed(d, _packet(), "10.0.0.5")
    _feed(d, _packet(), "10.0.0.9")
    assert d.peers["bob"]["ip"] == "10.0.0.9"