#!/usr/bin/env python3
"""Validate the rendered chart's storage, networking, and Silver configuration."""

import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parents[2] / "charts" / "silver"


def render(values=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as values_file:
        yaml.safe_dump(values or {}, values_file)
        values_file.flush()
        result = subprocess.run(
            ["helm", "template", "test", str(CHART), "-f", values_file.name],
            capture_output=True,
            text=True,
            check=True,
        )
    return list(yaml.safe_load_all(result.stdout))


def statefulset(documents):
    return next(item for item in documents if item["kind"] == "StatefulSet")


class ChartTests(unittest.TestCase):
    def test_defaults(self):
        subprocess.run(["helm", "lint", "--strict", str(CHART)], check=True)
        documents = render()
        workload = statefulset(documents)
        pod = workload["spec"]["template"]["spec"]
        container = pod["containers"][0]
        app_version = yaml.safe_load((CHART / "Chart.yaml").read_text())["appVersion"]
        self.assertEqual(container["image"], f"ghcr.io/gattaca-com/silver:{app_version}")
        self.assertEqual(pod["nodeSelector"]["kubernetes.io/arch"], "amd64")
        self.assertIn({"name": "RUST_LOG", "value": "info"}, container["env"])
        self.assertEqual(workload["spec"]["volumeClaimTemplates"][0]["metadata"]["name"], "data")
        ports = {port["name"]: port for port in container["ports"]}
        for name, number in (("p2p-udp", 31133), ("p2p-quic", 31123)):
            self.assertEqual(ports[name]["hostPort"], number)
            self.assertEqual(ports[name]["protocol"], "UDP")
        self.assertEqual(container["readinessProbe"]["httpGet"]["path"], "/eth/v1/node/health?syncing_status=503")
        self.assertEqual(container["livenessProbe"]["httpGet"]["path"], "/eth/v1/node/version")

    def test_config_and_jwt(self):
        documents = render({
            "externalIP": {"enabled": False},
            "jwtSecret": {"existingSecret": "execution-jwt", "key": "jwt.hex"},
            "image": {"tag": "v9.8.7"},
            "service": {"rpc": {"port": 5052}, "p2p": {"enableHostPort": False, "udp": {"port": 32133}, "quic": {"port": 32123}}},
            "extraArgs": {"network": "hoodi", "execution-endpoint": "http://execution:8551"},
            "config": "attestation_subnet_count = 4\n[engine_config]\nexecution_timeout_ms = 5000\n",
        })
        pod = statefulset(documents)["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertNotIn("initContainers", pod)
        self.assertEqual(container["image"], "ghcr.io/gattaca-com/silver:v9.8.7")
        self.assertIn("--jwt-secret=/jwt-secret/jwt", container["args"])
        self.assertIn("--network=hoodi", container["args"])
        self.assertTrue(all("hostPort" not in port for port in container["ports"]))
        secret = next(volume["secret"] for volume in pod["volumes"] if volume["name"] == "jwt-secret")
        self.assertEqual(secret, {"secretName": "execution-jwt", "items": [{"key": "jwt.hex", "path": "jwt"}]})
        config = next(item["data"]["config.toml"] for item in documents if item["kind"] == "ConfigMap" and "config.toml" in item["data"])
        parsed = tomllib.loads(config)
        self.assertEqual(parsed["data_storage_dir"], "/data")
        self.assertEqual(parsed["beacon_api_bind"], ["0.0.0.0:5052"])
        self.assertEqual(parsed["discovery_port"], 32133)
        self.assertEqual(parsed["quic_port"], 32123)
        self.assertEqual(parsed["attestation_subnet_count"], 4)

    def test_storage_modes(self):
        for mode, settings, expected in (
            ("emptyDir", {}, {"emptyDir": {}}),
            ("existingClaim", {"existingClaim": "silver-data"}, {"persistentVolumeClaim": {"claimName": "silver-data"}}),
            ("hostPath", {"hostPath": {"path": "/var/lib/silver"}}, {"hostPath": {"path": "/var/lib/silver", "type": "Directory"}}),
        ):
            with self.subTest(mode=mode):
                workload = statefulset(render({"persistence": {"type": mode, **settings}}))
                self.assertNotIn("volumeClaimTemplates", workload["spec"])
                volumes = workload["spec"]["template"]["spec"]["volumes"]
                self.assertIn({"name": "data", **expected}, volumes)

    def test_monitor_and_external_ip(self):
        documents = render({"serviceMonitor": {"enabled": True}, "externalIP": {"value": "192.0.2.10"}})
        monitor = next(item for item in documents if item["kind"] == "ServiceMonitor")
        self.assertEqual(monitor["spec"]["endpoints"][0]["port"], "metrics")
        init = statefulset(documents)["spec"]["template"]["spec"]["initContainers"][0]
        self.assertIn({"name": "EXTERNAL_IP", "value": "192.0.2.10"}, init["env"])

    def test_invalid_values_fail(self):
        for values in (
            {"persistence": {"type": "existingClaim"}},
            {"persistence": {"type": "hostPath"}},
            {"extraArgs": {"config": "/override.toml"}},
            {"replicaCount": -1},
        ):
            with self.subTest(values=values), self.assertRaises(subprocess.CalledProcessError):
                render(values)


if __name__ == "__main__":
    unittest.main()
