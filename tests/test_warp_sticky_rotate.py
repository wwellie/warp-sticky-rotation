import contextlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "warp_sticky_rotate.py"
spec = importlib.util.spec_from_file_location("warp_sticky_rotate", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class BackendReadinessTests(unittest.TestCase):
    def test_probe_rejects_generation_change_during_trace(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="ip=2001:db8::1\nwarp=on\n",
            stderr="",
        )
        with (
            mock.patch.object(module, "container_info", side_effect=[(True, "gen-1"), (True, "gen-2")]),
            mock.patch.object(module, "run_command", return_value=completed),
        ):
            with self.assertRaisesRegex(module.RuntimeFault, "generation changed"):
                module.probe_backend("warp3")

    def test_probe_disables_no_proxy_bypass(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="ip=2001:db8::1\nwarp=on\n",
            stderr="",
        )
        with (
            mock.patch.object(module, "container_info", return_value=(True, "gen-1")),
            mock.patch.object(module, "run_command", return_value=completed) as runner,
        ):
            module.probe_backend("warp3", container_ref="a" * 64)
        argv = runner.call_args.args[0]
        self.assertIn("NO_PROXY=", argv)
        self.assertIn("no_proxy=", argv)
        self.assertEqual(argv[argv.index("--noproxy") + 1], "")

    def test_active_backend_is_reprobed_even_when_generation_is_unchanged(self):
        state = module.default_state()
        state["tags"]["warp5"].update(
            {
                "phase": "active",
                "generation": "gen-1",
                "container_id": "a" * 64,
                "ip": "2001:db8::old",
            }
        )
        with (
            mock.patch.object(
                module, "container_identity", return_value=(True, "gen-1", "a" * 64)
            ),
            mock.patch.object(module, "probe_backend", return_value=("2001:db8::new", "gen-1")) as probe,
        ):
            module.refresh_entry_if_generation_changed(state, "warp5", force_probe=True)
        probe.assert_called_once_with("warp5", container_ref="a" * 64)
        self.assertEqual(state["tags"]["warp5"]["ip"], "2001:db8::new")

    def test_active_probe_failure_is_fatal_and_clears_cached_ip(self):
        state = module.default_state()
        state["tags"]["warp5"].update(
            {
                "phase": "active",
                "generation": "gen-1",
                "container_id": "a" * 64,
                "ip": "2001:db8::stale",
            }
        )
        with (
            mock.patch.object(
                module, "container_identity", return_value=(True, "gen-1", "a" * 64)
            ),
            mock.patch.object(
                module,
                "probe_backend",
                side_effect=module.RuntimeFault("fresh active probe failed"),
            ),
        ):
            with self.assertRaisesRegex(module.RuntimeFault, "fresh active probe failed"):
                module.refresh_entry_if_generation_changed(state, "warp5", force_probe=True)
        self.assertEqual(state["tags"]["warp5"]["ip"], "")

    def test_active_backend_not_running_clears_identity_and_fails_closed(self):
        state = module.default_state()
        state["tags"]["warp5"].update(
            {
                "phase": "active",
                "generation": "gen-1",
                "container_id": "a" * 64,
                "ip": "2001:db8::stale",
            }
        )
        with mock.patch.object(module, "container_identity", return_value=(False, "", "")):
            with self.assertRaisesRegex(module.RuntimeFault, "active backend warp5 is not running"):
                module.refresh_entry_if_generation_changed(state, "warp5", force_probe=True)
        entry = state["tags"]["warp5"]
        self.assertEqual(entry["phase"], "failed")
        self.assertEqual(entry["ip"], "")
        self.assertEqual(entry["generation"], "")
        self.assertEqual(entry["container_id"], "")
        self.assertEqual(entry["last_error"], "container_not_running")

    def test_active_probe_rejects_same_name_container_replacement(self):
        state = module.default_state()
        state["tags"]["warp5"].update(
            {
                "phase": "active",
                "generation": "gen-1",
                "container_id": "a" * 64,
                "ip": "2001:db8::old",
            }
        )
        with (
            mock.patch.object(
                module,
                "container_identity",
                side_effect=[
                    (True, "gen-1", "a" * 64),
                    (True, "gen-2", "b" * 64),
                ],
            ),
            mock.patch.object(module, "probe_backend", return_value=("2001:db8::new", "gen-1")),
        ):
            with self.assertRaisesRegex(module.RuntimeFault, "name no longer maps"):
                module.refresh_entry_if_generation_changed(state, "warp5", force_probe=True)
        self.assertEqual(state["tags"]["warp5"]["ip"], "")

    def test_candidate_is_not_ready_when_fresh_warp_probe_fails(self):
        entry = {"generation": "gen-1", "container_id": "a" * 64, "ip": "2001:db8::1"}
        with (
            mock.patch.object(module, "front_socks_path_ready", return_value=True) as socks,
            mock.patch.object(module, "probe_backend", side_effect=module.RuntimeFault("warp unavailable")),
        ):
            self.assertFalse(module.locally_ready("warp3", entry))
        socks.assert_called_once_with("warp3")

    def test_candidate_is_not_ready_when_front_socks_protocol_path_fails(self):
        entry = {"generation": "gen-1", "container_id": "a" * 64, "ip": "2001:db8::1"}
        with (
            mock.patch.object(module, "front_socks_path_ready", return_value=False),
            mock.patch.object(module, "probe_backend") as probe,
        ):
            self.assertFalse(module.locally_ready("warp3", entry))
        probe.assert_not_called()

    def test_front_socks_path_ready_requires_method_and_connect_success(self):
        ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        bad = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        with mock.patch.object(module, "run_command", return_value=ok) as runner:
            self.assertTrue(module.front_socks_path_ready("warp4"))
        argv = runner.call_args.args[0]
        self.assertEqual(
            argv[:9],
            ["docker", "exec", "singbox-warp", "timeout", "-k", "1", "6", "bash", "-c"],
        )
        script = argv[9]
        self.assertIn("/dev/tcp/warp4/1081", script)
        self.assertIn("\\x05\\x01\\x00", script)
        self.assertIn("050000", script)
        self.assertIn('01) read_hex 6', script)
        self.assertIn('04) read_hex 18', script)
        self.assertIn('03)', script)
        self.assertEqual(runner.call_args.kwargs["timeout"], 8)
        with mock.patch.object(module, "run_command", return_value=bad):
            self.assertFalse(module.front_socks_path_ready("warp4"))


class DockerNetworkTests(unittest.TestCase):
    def test_auto_detects_single_shared_network(self):
        networks = {
            "front": {"frontend", "warp-net"},
            "warp3": {"warp-net"},
            "warp4": {"warp-net", "metrics"},
            "warp5": {"warp-net"},
        }
        self.assertEqual(module.select_shared_network(networks), "warp-net")

    def test_configured_network_must_be_shared(self):
        networks = {"front": {"warp-net"}, "warp3": {"other-net"}}
        with self.assertRaisesRegex(ValueError, "not shared"):
            module.select_shared_network(networks, "warp-net")

    def test_ambiguous_auto_detection_fails_closed(self):
        networks = {"front": {"a", "b"}, "warp3": {"a", "b"}}
        with self.assertRaisesRegex(ValueError, "exactly one"):
            module.select_shared_network(networks)


class RingSelectionTests(unittest.TestCase):
    def test_ordered_after_wraps_in_fixed_three_exit_ring(self):
        self.assertEqual(
            module.ordered_after("warp5", ("warp3", "warp4", "warp5")),
            ["warp3", "warp4"],
        )

    def test_choose_candidate_skips_draining_failed_and_same_ip(self):
        state = {
            "tags": {
                "warp3": {"phase": "draining", "ip": "2001:db8::3"},
                "warp4": {"phase": "ready", "ip": "2001:db8::5"},
                "warp5": {"phase": "active", "ip": "2001:db8::5"},
            }
        }
        self.assertIsNone(
            module.choose_candidate(
                "warp5",
                state,
                ("warp3", "warp4", "warp5"),
                is_locally_ready=lambda _tag, _entry: True,
            )
        )

    def test_choose_candidate_rechecks_ip_after_fresh_readiness_probe(self):
        state = {
            "tags": {
                "warp3": {"phase": "ready", "ip": "2001:db8::3"},
                "warp4": {"phase": "draining", "ip": "2001:db8::4"},
                "warp5": {"phase": "active", "ip": "2001:db8::5"},
            }
        }

        def refresh_ip(_tag, entry):
            entry["ip"] = "2001:db8::5"
            return True

        self.assertIsNone(
            module.choose_candidate(
                "warp5",
                state,
                ("warp3", "warp4", "warp5"),
                is_locally_ready=refresh_ip,
            )
        )

    def test_choose_candidate_uses_first_ready_exit_in_ring_order(self):
        state = {
            "tags": {
                "warp3": {"phase": "ready", "ip": "2001:db8::3"},
                "warp4": {"phase": "ready", "ip": "2001:db8::4"},
                "warp5": {"phase": "active", "ip": "2001:db8::5"},
            }
        }
        self.assertEqual(
            module.choose_candidate(
                "warp5",
                state,
                ("warp3", "warp4", "warp5"),
                is_locally_ready=lambda _tag, _entry: True,
            ),
            "warp3",
        )


class SelectorConfigurationTests(unittest.TestCase):
    @staticmethod
    def valid_config(secret="test-secret"):
        return {
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "0.0.0.0",
                    "listen_port": 1081,
                }
            ],
            "outbounds": [
                {
                    "type": "selector",
                    "tag": "warp-active",
                    "outbounds": ["warp3", "warp4", "warp5"],
                    "default": "warp3",
                    "interrupt_exist_connections": False,
                },
                *[
                    {
                        "type": "socks",
                        "tag": tag,
                        "server": tag,
                        "server_port": 1081,
                        "version": "5",
                    }
                    for tag in ("warp3", "warp4", "warp5")
                ],
            ],
            "route": {"final": "warp-active"},
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": secret,
                }
            },
        }

    def test_runtime_selector_requires_exact_three_exit_ring(self):
        valid = {
            "type": "Selector",
            "now": "warp3",
            "all": ["warp3", "warp4", "warp5"],
        }
        self.assertEqual(module.validate_selector_payload(valid), "warp3")
        invalid = dict(valid, all=["warp3", "warp4", "warp5", "warp-extra"])
        with self.assertRaisesRegex(module.RuntimeFault, "outbound list"):
            module.validate_selector_payload(invalid)

    def test_config_requires_complete_authenticated_fixed_topology(self):
        module.validate_singbox_config(self.valid_config(), expected_secret="test-secret")
        invalid_cases = {
            "selector-default": lambda config: config["outbounds"][0].update(default="direct"),
            "selector-interrupt": lambda config: config["outbounds"][0].update(
                interrupt_exist_connections=True
            ),
            "extra-outbound": lambda config: config["outbounds"].append(
                {"type": "direct", "tag": "direct"}
            ),
            "inbound": lambda config: config["inbounds"][0].update(listen_port=9999),
            "extra-inbound": lambda config: config["inbounds"].append(
                {"type": "http", "tag": "extra", "listen": "::", "listen_port": 1080}
            ),
            "route": lambda config: config["route"].update(final="direct"),
            "route-rule": lambda config: config["route"].update(
                rules=[{"inbound": ["socks-in"], "outbound": "direct"}]
            ),
            "backend": lambda config: config["outbounds"][1].update(type="direct"),
            "backend-detour": lambda config: config["outbounds"][1].update(detour="warp4"),
            "backend-network": lambda config: config["outbounds"][1].update(network="udp"),
            "secret": lambda config: config["experimental"]["clash_api"].update(secret=""),
        }
        for name, mutate in invalid_cases.items():
            with self.subTest(name=name):
                config = self.valid_config()
                mutate(config)
                with self.assertRaises(module.RuntimeFault):
                    module.validate_singbox_config(config, expected_secret="test-secret")

    def test_config_accepts_ipv6_wildcard_for_fixed_socks_inbound(self):
        config = self.valid_config()
        config["inbounds"][0]["listen"] = "::"
        module.validate_singbox_config(config, expected_secret="test-secret")

    def test_runtime_verification_rejects_config_modified_after_container_start(self):
        config = self.valid_config()
        cat_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(config), stderr=""
        )
        stat_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="1970-01-01 00:01:40.200000000 +0000\n",
            stderr="",
        )
        with (
            mock.patch.object(module, "run_command", side_effect=[cat_result, stat_result]),
            mock.patch.object(module, "docker_network", return_value="test-network"),
            mock.patch.object(module, "container_info", return_value=(True, "1970-01-01T00:01:40.100000Z")),
            mock.patch.object(module, "clash_secret", return_value="test-secret"),
        ):
            with self.assertRaisesRegex(module.RuntimeFault, "modified after"):
                module.verify_singbox_config()


class ClashRequestTests(unittest.TestCase):
    def test_valid_chunked_response_is_decoded(self):
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
                b"8; extension=value\r\n"
                b'{"connec'
                b"\r\n"
                b"A\r\n"
                b'tions":[]}\r\n'
                b"0\r\n"
                b"X-Trailer: done\r\n\r\n"
            ),
            stderr=b"",
        )
        with (
            mock.patch.object(module, "clash_secret", return_value="test-secret"),
            mock.patch.object(module, "run_command", return_value=response),
        ):
            self.assertEqual(module.clash_request("/connections"), {"connections": []})

    def test_control_request_uses_container_loopback_and_stdin(self):
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            stderr=b"",
        )
        with (
            mock.patch.object(module, "clash_secret", return_value="test-secret"),
            mock.patch.object(module, "run_command", return_value=response) as runner,
        ):
            self.assertEqual(
                module.clash_request(
                    "/proxies/warp-active",
                    method="PUT",
                    payload={"name": "warp4"},
                ),
                {},
            )
        argv = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertEqual(
            argv,
            ["docker", "exec", "-i", "singbox-warp", "nc", "-w", "5", "127.0.0.1", "9090"],
        )
        request = kwargs["input_text"]
        self.assertIn("PUT /proxies/warp-active HTTP/1.1", request)
        self.assertIn("Authorization: Bearer test-secret", request)
        self.assertIn('{"name":"warp4"}', request)
        self.assertNotIn("test-secret", " ".join(argv))
        self.assertIs(kwargs["binary"], True)

    def test_missing_secret_fails_closed_before_control_request(self):
        with (
            mock.patch.object(module, "CLASH_SECRET_PATH", Path("/definitely/missing/secret")),
            mock.patch.object(module, "run_command") as runner,
        ):
            with self.assertRaisesRegex(module.RuntimeFault, "secret file unavailable"):
                module.clash_request("/proxies/test")
        runner.assert_not_called()

    def test_secret_line_breaks_fail_before_control_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash.secret"
            path.write_text("test-secret\r\nInjected: value", encoding="utf-8")
            os.chmod(path, 0o600)
            with mock.patch.object(module, "CLASH_SECRET_PATH", path):
                with self.assertRaisesRegex(module.RuntimeFault, "forbidden line breaks"):
                    module.clash_secret()

    def test_secret_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("test-secret", encoding="utf-8")
            os.chmod(target, 0o600)
            link = Path(directory) / "clash.secret"
            link.symlink_to(target)
            with mock.patch.object(module, "CLASH_SECRET_PATH", link):
                with self.assertRaisesRegex(module.RuntimeFault, "file unavailable"):
                    module.clash_secret()

    def test_control_request_ignores_ambient_proxy_environment(self):
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            stderr=b"",
        )
        with (
            mock.patch.dict(
                module.os.environ,
                {"HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9"},
            ),
            mock.patch.object(module, "clash_secret", return_value="test-secret"),
            mock.patch.object(module, "run_command", return_value=response) as runner,
        ):
            module.clash_request("/connections")
        self.assertEqual(runner.call_args.args[0][0:4], ["docker", "exec", "-i", "singbox-warp"])

    def test_malformed_or_truncated_http_response_fails_closed(self):
        responses = (
            b"NOTHTTP 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\nContent-Length: 2\n\n{}",
            b"HTTP/1.1 200 OK\rContent-Length: 2\r\r{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: ٢\r\n\r\n{}".encode(),
            b"HTTP/1.1 200 OK\r\nX-Test: bad\x7fvalue\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}",
        )
        for raw in responses:
            with self.subTest(raw=raw):
                result = subprocess.CompletedProcess(args=[], returncode=0, stdout=raw, stderr=b"")
                with (
                    mock.patch.object(module, "clash_secret", return_value="test-secret"),
                    mock.patch.object(module, "run_command", return_value=result),
                ):
                    with self.assertRaisesRegex(module.RuntimeFault, "invalid HTTP response"):
                        module.clash_request("/connections")


class ConnectionDrainTests(unittest.TestCase):
    def test_connection_count_for_tag_counts_matching_chains_without_requiring_id(self):
        payload = {
            "connections": [
                {"id": "old-1", "chains": ["warp5", "warp-active"]},
                {"id": "new-1", "chains": ["warp3", "warp-active"]},
                {"chains": ["warp5", "warp-active"]},
            ]
        }
        self.assertEqual(module.connection_count_for_tag(payload, "warp5"), 2)

    def test_connection_count_fails_closed_on_invalid_payload(self):
        malformed = [
            {"connections": "not-a-list"},
            {"connections": [None]},
            {"connections": [{"chains": None}]},
            {"connections": [{"chains": []}]},
            {"connections": [{"chains": [" "]}]},
            {"connections": [{"chains": ["warp5", ""]}]},
        ]
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                module.connection_count_for_tag(payload, "warp5")

    def test_backend_client_connection_count_counts_connected_socks_clients(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "0 0 192.0.2.8:1081 198.51.100.5:41962\n"
                "0 0 192.0.2.8:1081 198.51.100.6:50000\n"
            ),
            stderr="",
        )
        with mock.patch.object(module, "run_command", return_value=completed) as runner:
            self.assertEqual(module.backend_client_connection_count("warp3"), 2)
        argv = runner.call_args.args[0]
        self.assertEqual(argv[:4], ["docker", "exec", "warp3", "ss"])
        self.assertIn("connected", argv)
        self.assertIn("( sport = :1081 )", argv)

    def test_admission_barrier_rejects_only_new_port_1081_connections(self):
        for firewall in ("iptables", "ip6tables"):
            with self.subTest(firewall=firewall):
                argv = module._barrier_rule_argv("warp3", firewall, "-I")
                self.assertEqual(argv[:4], ["docker", "exec", "warp3", firewall])
                self.assertEqual(argv[argv.index("INPUT") + 1], "1")
                self.assertIn("conntrack", argv)
                self.assertIn("NEW", argv)
                self.assertIn("lo", argv)
                self.assertIn("1081", argv)
                self.assertIn("tcp-reset", argv)

    def test_install_barrier_applies_ipv4_and_ipv6(self):
        absent = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with mock.patch.object(
            module,
            "run_command",
            side_effect=[absent, success, success, absent, success, success],
        ) as runner:
            module.install_admission_barrier("warp3")
        firewalls = [call.args[0][3] for call in runner.call_args_list]
        self.assertEqual(firewalls, ["iptables"] * 3 + ["ip6tables"] * 3)

    def test_verify_barrier_fails_if_either_protocol_family_is_missing(self):
        results = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
        ]
        with mock.patch.object(module, "run_command", side_effect=results):
            with self.assertRaisesRegex(module.RuntimeFault, "not continuous"):
                module.verify_admission_barrier("warp3")

    def test_remove_barrier_cleans_ipv4_and_ipv6(self):
        present = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        absent = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        with mock.patch.object(
            module,
            "run_command",
            side_effect=[present, present, absent, present, present, absent],
        ) as runner:
            module.remove_admission_barrier("warp3")
        firewalls = [call.args[0][3] for call in runner.call_args_list]
        self.assertEqual(firewalls, ["iptables"] * 3 + ["ip6tables"] * 3)


class StateTransitionTests(unittest.TestCase):
    def test_missing_drain_generation_fails_closed_without_barrier_or_refresh(self):
        state = module.default_state()
        state["tags"]["warp3"].update({"phase": "draining", "generation": ""})
        with (
            mock.patch.object(module, "file_lock", side_effect=lambda *args, **kwargs: contextlib.nullcontext()),
            mock.patch.object(module, "load_state", return_value=state),
            mock.patch.object(module, "verify_singbox_config"),
            mock.patch.object(module, "save_state") as save_state,
            mock.patch.object(module, "install_admission_barrier") as install_barrier,
            mock.patch.object(module, "run_command") as run_command,
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 1)
        self.assertEqual(state["tags"]["warp3"]["phase"], "unknown")
        self.assertEqual(state["tags"]["warp3"]["last_error"], "missing_drain_identity_no_refresh")
        save_state.assert_called_once_with(state)
        install_barrier.assert_not_called()
        run_command.assert_not_called()

    def test_reconcile_manual_selector_change_preserves_old_active_as_draining(self):
        state = {
            "version": 1,
            "tags": {
                "warp3": {"phase": "ready", "ip": "ip3"},
                "warp4": {"phase": "active", "ip": "ip4"},
                "warp5": {"phase": "ready", "ip": "ip5"},
            },
        }
        pending = module.reconcile_selector_state(
            state,
            "warp3",
            ("warp3", "warp4", "warp5"),
            now=100.0,
        )
        self.assertEqual(state["tags"]["warp3"]["phase"], "active")
        self.assertEqual(state["tags"]["warp4"]["phase"], "draining")
        self.assertEqual(len(state["tags"]["warp4"]["drain_id"]), 32)
        self.assertEqual(state["tags"]["warp4"]["drain_generation"], "")
        self.assertEqual(pending, ["warp4"])

    def test_expired_failed_backend_waits_for_identity_recovery_instead_of_redrain(self):
        state = module.default_state()
        state["tags"]["warp3"].update(
            {
                "phase": "failed",
                "generation": "stale-generation",
                "container_id": "a" * 64,
                "retry_after": 10.0,
            }
        )
        pending = module.reconcile_selector_state(state, "warp4", now=11.0)
        self.assertEqual(pending, [])
        self.assertEqual(state["tags"]["warp3"]["phase"], "failed")

    def test_failed_backend_recovers_with_fresh_identity_after_cooldown(self):
        state = module.default_state()
        entry = state["tags"]["warp3"]
        entry.update(
            {
                "phase": "failed",
                "generation": "stale-generation",
                "container_id": "a" * 64,
                "drain_generation": "stale-generation",
                "drain_container_id": "a" * 64,
                "drain_id": "stale-drain",
                "retry_after": 10.0,
            }
        )
        with (
            mock.patch.object(
                module,
                "container_identity",
                side_effect=[
                    (True, "fresh-generation", "b" * 64),
                    (True, "fresh-generation", "b" * 64),
                ],
            ),
            mock.patch.object(module, "install_admission_barrier") as install_barrier,
            mock.patch.object(
                module,
                "probe_backend",
                return_value=("2001:db8::30", "fresh-generation"),
            ),
            mock.patch.object(module, "remove_admission_barrier") as remove_barrier,
        ):
            self.assertTrue(module.recover_failed_entry(state, "warp3", now=11.0))
        install_barrier.assert_called_once_with("b" * 64)
        remove_barrier.assert_called_once_with("b" * 64)
        self.assertEqual(entry["phase"], "ready")
        self.assertEqual(entry["generation"], "fresh-generation")
        self.assertEqual(entry["container_id"], "b" * 64)
        self.assertNotIn("drain_id", entry)

    def test_apply_switch_marks_old_draining_and_new_active(self):
        state = {
            "version": 1,
            "tags": {
                "warp3": {"phase": "ready", "ip": "ip3", "generation": "gen3"},
                "warp4": {"phase": "ready", "ip": "ip4", "generation": "gen4"},
                "warp5": {"phase": "active", "ip": "ip5", "generation": "gen5"},
            },
        }
        module.apply_switch(state, old="warp5", new="warp3", now=200.0, switch_ms=7.5)
        self.assertEqual(state["active"], "warp3")
        self.assertEqual(state["tags"]["warp3"]["phase"], "active")
        self.assertEqual(state["tags"]["warp5"]["phase"], "draining")
        self.assertEqual(state["tags"]["warp5"]["old_ip"], "ip5")
        self.assertEqual(state["tags"]["warp5"]["drain_generation"], "gen5")
        self.assertEqual(len(state["tags"]["warp5"]["drain_id"]), 32)
        self.assertEqual(state["last_switch_ms"], 7.5)


class DrainRefreshSafetyTests(unittest.TestCase):
    @staticmethod
    def draining_state():
        state = module.default_state()
        state["tags"]["warp3"].update(
            {
                "phase": "draining",
                "ip": "2001:db8::10",
                "old_ip": "2001:db8::10",
                "generation": "gen-old",
                "container_id": "a" * 64,
                "drain_generation": "gen-old",
                "drain_container_id": "a" * 64,
                "drain_id": "drain-1",
            }
        )
        state["tags"]["warp4"].update({"phase": "active", "ip": "2001:db8::20"})
        return state

    @contextlib.contextmanager
    def base_context(self, state):
        with contextlib.ExitStack() as stack:
            for patcher in (
                mock.patch.object(
                    module,
                    "file_lock",
                    side_effect=lambda *args, **kwargs: contextlib.nullcontext(),
                ),
                mock.patch.object(module, "verify_singbox_config"),
                mock.patch.object(module, "load_state", return_value=state),
                mock.patch.object(module, "save_state"),
                mock.patch.object(
                    module,
                    "container_identity",
                    return_value=(True, "gen-old", "a" * 64),
                ),
                mock.patch.object(module, "install_admission_barrier"),
                mock.patch.object(module, "verify_admission_barrier"),
                mock.patch.object(module, "remove_admission_barrier"),
                mock.patch.object(module, "selector_now", return_value="warp4"),
                mock.patch.object(module.time, "sleep"),
                mock.patch.object(module, "DRAIN_ZERO_SAMPLES", 2),
                mock.patch.object(module, "REFRESH_ATTEMPTS", 1),
            ):
                stack.enter_context(patcher)
            yield

    def test_success_requires_two_zero_samples_and_final_zero_recheck(self):
        state = self.draining_state()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="warp3\n", stderr="")
        with (
            self.base_context(state),
            mock.patch.object(module, "connections_for_tag", side_effect=[1, 0, 0, 0]) as clash_count,
            mock.patch.object(module, "backend_client_connection_count", side_effect=[1, 0, 0, 0]) as backend_count,
            mock.patch.object(module, "container_info", return_value=(True, "gen-old")),
            mock.patch.object(module, "run_command", return_value=success) as runner,
            mock.patch.object(module, "verify_admission_barrier") as verify_barrier,
            mock.patch.object(module, "probe_backend", return_value=("2001:db8::11", "gen-old")),
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 0)
        self.assertEqual(clash_count.call_count, 4)
        self.assertEqual(backend_count.call_count, 4)
        verify_barrier.assert_called_once_with("a" * 64)
        argv = runner.call_args.args[0]
        self.assertEqual(
            argv[:6],
            ["docker", "exec", "a" * 64, "sh", "-eu", "-c"],
        )
        refresh_script = argv[6]
        self.assertIn("mktemp -d /run/warp-sticky-wg.XXXXXX", refresh_script)
        self.assertIn(f"grep -Eiq '{module.WG_HOOK_PATTERN}'", refresh_script)
        self.assertIn('wg-quick down "$tmpdir/wg0.conf"', refresh_script)
        self.assertIn('wg-quick up "$tmpdir/wg0.conf"', refresh_script)
        self.assertEqual(runner.call_args.kwargs, {"timeout": 40})
        entry = state["tags"]["warp3"]
        self.assertEqual(entry["phase"], "ready")
        self.assertEqual(entry["ip"], "2001:db8::11")
        self.assertNotIn("drain_id", entry)
        self.assertNotIn("drain_generation", entry)
        self.assertNotIn("drain_container_id", entry)

    def test_wireguard_hook_guard_matches_case_and_leading_whitespace(self):
        for line in (
            "PreUp = /bin/false\n",
            "  PreUp = /bin/false\n",
            "preup = /bin/false\n",
            "\tPOSTDOWN = /bin/false\n",
        ):
            with self.subTest(line=line):
                result = subprocess.run(
                    ["grep", "-Eiq", module.WG_HOOK_PATTERN],
                    input=line,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)

    def test_generation_change_fails_after_unconditional_final_inventory(self):
        state = self.draining_state()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with (
            self.base_context(state),
            mock.patch.object(module, "connections_for_tag", side_effect=[0, 0, 0]) as clash_count,
            mock.patch.object(
                module,
                "backend_client_connection_count",
                side_effect=[0, 0, 0],
            ) as backend_count,
            mock.patch.object(module, "container_info", return_value=(True, "gen-replaced")),
            mock.patch.object(module, "probe_backend", return_value=("2001:db8::11", "gen-replaced")),
            mock.patch.object(module, "run_command", return_value=success) as runner,
            mock.patch.object(module, "remove_admission_barrier") as remove_barrier,
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 1)
        self.assertEqual(clash_count.call_count, 3)
        self.assertEqual(backend_count.call_count, 3)
        runner.assert_not_called()
        remove_barrier.assert_not_called()
        self.assertEqual(state["tags"]["warp3"]["phase"], "failed")
        self.assertEqual(state["tags"]["warp3"]["generation"], "gen-replaced")
        self.assertEqual(state["tags"]["warp3"]["container_id"], "a" * 64)
        self.assertNotIn("drain_id", state["tags"]["warp3"])

    def test_name_replacement_cannot_complete_refresh_for_bound_container(self):
        state = self.draining_state()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with (
            self.base_context(state),
            mock.patch.object(module, "connections_for_tag", return_value=0),
            mock.patch.object(module, "backend_client_connection_count", return_value=0),
            mock.patch.object(module, "container_info", return_value=(True, "gen-old")),
            mock.patch.object(
                module,
                "container_identity",
                return_value=(True, "gen-new", "b" * 64),
            ),
            mock.patch.object(module, "probe_backend", return_value=("2001:db8::11", "gen-new")),
            mock.patch.object(module, "run_command", return_value=success),
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 1)
        self.assertNotEqual(state["tags"]["warp3"]["phase"], "ready")

    def test_final_live_inventory_defers_refresh_and_keeps_barrier(self):
        state = self.draining_state()
        with (
            self.base_context(state),
            mock.patch.object(module, "connections_for_tag", side_effect=[0, 0, 1]),
            mock.patch.object(module, "backend_client_connection_count", side_effect=[0, 0, 0]),
            mock.patch.object(module, "container_info", return_value=(True, "gen-old")),
            mock.patch.object(module, "run_command") as runner,
            mock.patch.object(module, "remove_admission_barrier") as remove_barrier,
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 0)
        runner.assert_not_called()
        remove_barrier.assert_not_called()
        self.assertEqual(state["tags"]["warp3"]["phase"], "draining")
        self.assertEqual(state["tags"]["warp3"]["last_clash_connection_count"], 1)

    def test_final_backend_inventory_defers_refresh(self):
        state = self.draining_state()
        with (
            self.base_context(state),
            mock.patch.object(module, "connections_for_tag", side_effect=[0, 0, 0]),
            mock.patch.object(module, "backend_client_connection_count", side_effect=[0, 0, 1]),
            mock.patch.object(module, "container_info", return_value=(True, "gen-old")),
            mock.patch.object(module, "run_command") as runner,
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 0)
        runner.assert_not_called()
        self.assertEqual(state["tags"]["warp3"]["phase"], "draining")
        self.assertEqual(state["tags"]["warp3"]["last_backend_client_count"], 1)

    def test_final_unknown_inventory_fails_service_without_refresh(self):
        state = self.draining_state()
        with (
            self.base_context(state),
            mock.patch.object(
                module,
                "connections_for_tag",
                side_effect=[0, 0, module.RuntimeFault("unknown inventory")],
            ),
            mock.patch.object(module, "backend_client_connection_count", side_effect=[0, 0]),
            mock.patch.object(module, "container_info", return_value=(True, "gen-old")),
            mock.patch.object(module, "run_command") as runner,
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 1)
        runner.assert_not_called()

    def test_selector_reactivation_aborts_without_refresh(self):
        state = self.draining_state()
        with (
            self.base_context(state),
            mock.patch.object(module, "selector_now", return_value="warp3"),
            mock.patch.object(module, "connections_for_tag") as clash_count,
            mock.patch.object(module, "backend_client_connection_count") as backend_count,
            mock.patch.object(module, "run_command") as runner,
            mock.patch.object(module, "remove_admission_barrier") as remove_barrier,
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 0)
        clash_count.assert_not_called()
        backend_count.assert_not_called()
        runner.assert_not_called()
        remove_barrier.assert_called_once_with("a" * 64)
        self.assertEqual(state["tags"]["warp3"]["phase"], "active")

    def test_failed_in_place_refresh_is_retried_before_ready(self):
        state = self.draining_state()
        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="refresh failed")
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="warp3\n", stderr="")
        with (
            self.base_context(state),
            mock.patch.object(module, "REFRESH_ATTEMPTS", 2),
            mock.patch.object(module, "connections_for_tag", side_effect=[0, 0, 0, 0]),
            mock.patch.object(module, "backend_client_connection_count", side_effect=[0, 0, 0, 0]),
            mock.patch.object(module, "container_info", return_value=(True, "gen-old")),
            mock.patch.object(module, "run_command", side_effect=[failed, success]) as runner,
            mock.patch.object(module, "probe_backend", return_value=("2001:db8::11", "gen-old")),
        ):
            self.assertEqual(module._drain_refresh_locked("warp3"), 0)
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(state["tags"]["warp3"]["phase"], "ready")


class DrainExitStatusTests(unittest.TestCase):
    def test_runtime_fault_is_reported_as_service_failure(self):
        with mock.patch.object(module, "file_lock", side_effect=module.RuntimeFault("inventory failed")):
            self.assertEqual(module.drain_refresh("warp3"), 1)


class SettingsValidationTests(unittest.TestCase):
    def test_rejects_any_nonfixed_topology(self):
        cases = {
            "RING": ("alpha", "beta", "gamma"),
            "SELECTOR": "other-selector",
            "SINGBOX_CONTAINER": "front",
            "CLASH_PORT": 9999,
            "BACKEND_SOCKS_PORT": 9999,
        }
        for name, value in cases.items():
            with self.subTest(name=name), mock.patch.object(module, name, value):
                with self.assertRaisesRegex(ValueError, "fixed topology"):
                    module.validate_settings()

    def test_rejects_invalid_trace_url(self):
        for value in (
            "http://example.test/trace",
            "https://user:password@example.test/trace",
            "https:///trace",
        ):
            with self.subTest(value=value), mock.patch.object(module, "TRACE_URL", value):
                with self.assertRaisesRegex(ValueError, "credential-free HTTPS"):
                    module.validate_settings()

    def test_rejects_unsafe_zero_sample_threshold(self):
        for threshold in (-1, 0, 1):
            with self.subTest(threshold=threshold), mock.patch.object(module, "DRAIN_ZERO_SAMPLES", threshold):
                with self.assertRaisesRegex(ValueError, "at least 2"):
                    module.validate_settings()

    def test_rejects_nonpositive_timeouts_and_attempts(self):
        for name in (
            "DRAIN_POLL_S",
            "REFRESH_ATTEMPTS",
            "REFRESH_POLL_S",
            "REFRESH_READY_TIMEOUT_S",
            "FAILED_RETRY_S",
        ):
            with self.subTest(name=name), mock.patch.object(module, name, 0):
                with self.assertRaisesRegex(ValueError, "positive setting required"):
                    module.validate_settings()

    def test_rejects_nonfinite_float_settings(self):
        for name in (
            "DRAIN_POLL_S",
            "REFRESH_POLL_S",
            "REFRESH_READY_TIMEOUT_S",
            "FAILED_RETRY_S",
        ):
            for value in (float("nan"), float("inf")):
                with self.subTest(name=name, value=value), mock.patch.object(module, name, value):
                    with self.assertRaisesRegex(ValueError, "finite positive setting required"):
                        module.validate_settings()

    def test_service_template_must_render_distinct_tagged_units(self):
        for template in (
            "warp-sticky-drain-refresh.service",
            "warp-sticky-{tag}/{tag}.service",
            "warp sticky@{tag}.service",
        ):
            with self.subTest(template=template), mock.patch.object(module, "SERVICE_TEMPLATE", template):
                with self.assertRaises(ValueError):
                    module.validate_settings()


if __name__ == "__main__":
    unittest.main()
