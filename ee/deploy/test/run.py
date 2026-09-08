"""Install and smoke-test the chart in a disposable, internet-isolated kind cluster."""

from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime, timedelta
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
import yaml

KEYCLOAK = "quay.io/keycloak/keycloak@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54"
VAULT = "hashicorp/vault@sha256:5520cc26271c024e6ffa45cdf95255bd26b70d71ba4b7e0bc18925bef4128adb"
HERE = Path(__file__).resolve().parent


def command(*args, data=None, capture=False, env=None):
    result = subprocess.run(
        args, input=data, text=True, check=True, capture_output=capture, env=env
    )
    return result.stdout.strip() if capture else ""


def certificates(directory):
    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Disposable shim smoke CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")]))
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("fixture"), x509.DNSName("keycloak")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "tls.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (directory / "tls.key").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def test_license(directory):
    key = ed25519.Ed25519PrivateKey.generate()
    (directory / "license_public_key.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "customer": "DISPOSABLE TEST ONLY - NEVER RELEASE",
                    "expires": (datetime.now(UTC) + timedelta(days=1))
                    .date()
                    .isoformat(),
                }
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    return (
        payload
        + "."
        + base64.urlsafe_b64encode(key.sign(payload.encode())).decode().rstrip("=")
    )


def kind_system_workload(item, cluster):
    metadata = item["metadata"]
    namespace = metadata.get("namespace")
    name = metadata["name"]
    known = {
        ("Deployment", "kube-system", "coredns"),
        ("Deployment", "local-path-storage", "local-path-provisioner"),
        ("DaemonSet", "kube-system", "kindnet"),
        ("DaemonSet", "kube-system", "kube-proxy"),
    }
    if (item["kind"], namespace, name) in known:
        return True
    if item["kind"] == "ReplicaSet":
        return any(
            kind == "Deployment"
            and namespace == ns
            and re.fullmatch(re.escape(deployment) + r"-[a-z0-9]+", name)
            for kind, ns, deployment in known
        )
    if item["kind"] != "Pod":
        return False
    owners = metadata.get("ownerReferences", [])
    if len(owners) != 1:
        return False
    owner = owners[0]
    if owner["kind"] == "DaemonSet":
        return ("DaemonSet", namespace, owner["name"]) in known
    if owner["kind"] == "ReplicaSet":
        return any(
            kind == "Deployment"
            and namespace == ns
            and re.fullmatch(re.escape(deployment) + r"-[a-z0-9]+", owner["name"])
            for kind, ns, deployment in known
        )
    return (
        namespace == "kube-system"
        and owner["kind"] == "Node"
        and owner["name"] == cluster + "-control-plane"
        and name
        in {
            component + "-" + cluster + "-control-plane"
            for component in (
                "etcd",
                "kube-apiserver",
                "kube-controller-manager",
                "kube-scheduler",
            )
        }
    )


def run(args):
    chart = args.chart.resolve()
    values = yaml.safe_load((chart / "values.yaml").read_text())
    directory = Path(tempfile.mkdtemp(prefix="shim-chart-smoke-"))
    directory.chmod(0o700)
    print(f"Disposable test material and diagnostics: {directory}", flush=True)
    certificates(directory)
    license_token = test_license(directory)
    images = [
        args.gateway_image,
        args.dashboard_image,
        args.node_image,
    ]
    for image in images:
        probe = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode:
            command("docker", "pull", image)
    original_image = command(
        "docker",
        "image",
        "inspect",
        args.gateway_image,
        "--format",
        "{{.Id}}",
        capture=True,
    )
    # Confirm the disposable signing key cannot authorize the unmodified image.
    verify = "import base64,sys; from importlib.resources import files; from cryptography.hazmat.primitives.serialization import load_pem_public_key; from cryptography.exceptions import InvalidSignature; p,s=sys.stdin.read().strip().split('.'); key=load_pem_public_key(files('shim_enterprise.core').joinpath('license_public_key.pem').read_bytes());\ntry: key.verify(base64.urlsafe_b64decode(s+'='*(-len(s)%4)),p.encode())\nexcept InvalidSignature: print('PASS production key rejects disposable licence')\nelse: raise SystemExit('Production image accepted disposable licence!')"
    command(
        "docker",
        "run",
        "--rm",
        "-i",
        "--entrypoint",
        "python",
        args.gateway_image,
        "-c",
        verify,
        data=license_token,
    )
    overlay = f"shim-on-prem-test-only:{uuid4().hex}"
    (directory / "Dockerfile").write_text(
        f"FROM {args.gateway_image}\nLABEL shim.test-only=true\nCOPY license_public_key.pem /app/.venv/lib/python3.13/site-packages/shim_enterprise/core/license_public_key.pem\n"
    )
    (directory / ".dockerignore").write_text(
        "*\n!Dockerfile\n!license_public_key.pem\n"
    )
    command("docker", "build", "--network=none", "-t", overlay, str(directory))
    assert original_image == command(
        "docker",
        "image",
        "inspect",
        args.gateway_image,
        "--format",
        "{{.Id}}",
        capture=True,
    )
    existing = command("kind", "get", "clusters", capture=True).splitlines()
    if args.cluster in existing and not args.reuse_empty_cluster:
        raise SystemExit(
            f"Cluster {args.cluster} already exists; explicitly remove that disposable cluster before running"
        )
    network = args.cluster + "-isolated"
    kubeconfig = directory / "kubeconfig"
    if args.cluster not in existing:
        command("docker", "network", "create", network)
    subnet = command(
        "docker",
        "network",
        "inspect",
        network,
        "--format",
        "{{(index .IPAM.Config 0).Subnet}}",
        capture=True,
    )
    environment = os.environ | {"KIND_EXPERIMENTAL_DOCKER_NETWORK": network}
    if args.cluster in existing:
        kubeconfig.write_text(
            command("kind", "get", "kubeconfig", "--name", args.cluster, capture=True)
        )
        workloads = json.loads(
            command(
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "get",
                "deployments,statefulsets,jobs,daemonsets,cronjobs,replicasets,pods,persistentvolumeclaims",
                "--all-namespaces",
                "-o",
                "json",
                capture=True,
            )
        )
        unexpected = [
            item
            for item in workloads["items"]
            if not kind_system_workload(item, args.cluster)
        ]
        if unexpected:
            raise SystemExit(
                "Refusing to reuse a cluster containing application workloads"
            )
    try:
        if args.cluster not in existing:
            command(
                "kind",
                "create",
                "cluster",
                "--name",
                args.cluster,
                "--image",
                args.node_image,
                "--kubeconfig",
                str(kubeconfig),
                "--retain",
                env=environment,
            )
        platform = command(
            "docker",
            "image",
            "inspect",
            args.gateway_image,
            "--format",
            "{{.Os}}/{{.Architecture}}",
            capture=True,
        )
        runtime_images = {}
        image_evidence = {}
        for image in [overlay, args.dashboard_image]:
            alias = "docker.io/library/shim-smoke-runtime:" + uuid4().hex
            runtime_images[image] = alias
            print(f"Loading {image} for {platform}", flush=True)
            with subprocess.Popen(
                ["docker", "image", "save", "--platform", platform, image],
                stdout=subprocess.PIPE,
            ) as exporting:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        "--privileged",
                        "-i",
                        args.cluster + "-control-plane",
                        "ctr",
                        "--namespace=k8s.io",
                        "images",
                        "import",
                        "--platform",
                        platform,
                        "--index-name",
                        alias,
                        "--digests",
                        "--snapshotter=overlayfs",
                        "-",
                    ],
                    stdin=exporting.stdout,
                    stdout=sys.stdout,
                    check=True,
                )
                exporting.stdout.close()
                if exporting.wait() != 0:
                    raise RuntimeError(f"Image export failed: {image}")
        for image in [
            KEYCLOAK,
            VAULT,
            values["postgres"]["image"],
            values["redis"]["image"],
        ]:
            first = image.split("/", 1)[0]
            alias = (
                image
                if "." in first
                else ("docker.io/" if "/" in image else "docker.io/library/") + image
            )
            if "@" in alias:
                repository, digest = alias.split("@", 1)
                alias = (
                    repository.rsplit(":", 1)[0] + "@" + digest
                    if ":" in repository.rsplit("/", 1)[-1]
                    else alias
                )
            runtime_images[image] = alias
            print(
                f"Pulling pinned fixture {alias} into node for {platform}", flush=True
            )
            command(
                "docker",
                "exec",
                args.cluster + "-control-plane",
                "ctr",
                "--namespace=k8s.io",
                "images",
                "pull",
                "--platform",
                platform,
                alias,
                capture=True,
            )
        for source, alias in runtime_images.items():
            info = json.loads(
                command(
                    "docker",
                    "exec",
                    args.cluster + "-control-plane",
                    "crictl",
                    "inspecti",
                    alias,
                    capture=True,
                )
            )
            image_evidence[source] = {
                "runtime_reference": alias,
                "runtime_image_id": info["status"]["id"],
                "platform": platform,
            }

        def kubectl(*parts, **kwargs):
            return command(
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "-n",
                "default",
                *parts,
                **kwargs,
            )

        node = args.cluster + "-control-plane"
        command(
            "docker",
            "exec",
            node,
            "timeout",
            "10",
            "bash",
            "-c",
            "exec 3<>/dev/tcp/1.1.1.1/443",
        )
        print("PASS node public-IP connectivity before isolation", flush=True)
        for binary, destinations in (
            ("iptables", [subnet, "10.244.0.0/16", "10.96.0.0/12"]),
            ("ip6tables", []),
        ):
            command("docker", "exec", node, binary, "-N", "SHIM_SMOKE_EGRESS")
            command(
                "docker",
                "exec",
                node,
                binary,
                "-A",
                "SHIM_SMOKE_EGRESS",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "RETURN",
            )
            command(
                "docker",
                "exec",
                node,
                binary,
                "-A",
                "SHIM_SMOKE_EGRESS",
                "-o",
                "lo",
                "-j",
                "RETURN",
            )
            for destination in destinations:
                command(
                    "docker",
                    "exec",
                    node,
                    binary,
                    "-A",
                    "SHIM_SMOKE_EGRESS",
                    "-d",
                    destination,
                    "-j",
                    "RETURN",
                )
            command(
                "docker",
                "exec",
                node,
                binary,
                "-A",
                "SHIM_SMOKE_EGRESS",
                "-j",
                "REJECT",
            )
            for chain in ("OUTPUT", "FORWARD"):
                command(
                    "docker",
                    "exec",
                    node,
                    binary,
                    "-I",
                    chain,
                    "1",
                    "-j",
                    "SHIM_SMOKE_EGRESS",
                )
        # Cluster service DNS remains; no upstream DNS forwarding leaves the node.
        dns = json.loads(
            kubectl(
                "-n",
                "kube-system",
                "get",
                "configmap",
                "coredns",
                "-o",
                "json",
                capture=True,
            )
        )
        dns["data"]["Corefile"] = re.sub(
            r"(?m)^\s*forward \. /etc/resolv.conf(?: \{[^}]*\})?\n",
            "\n",
            dns["data"]["Corefile"],
        )
        assert "forward ." not in dns["data"]["Corefile"]
        kubectl("-n", "kube-system", "apply", "-f", "-", data=json.dumps(dns))
        kubectl("-n", "kube-system", "rollout", "restart", "deployment/coredns")
        kubectl(
            "-n",
            "kube-system",
            "rollout",
            "status",
            "deployment/coredns",
            "--timeout=120s",
        )

        def apply(document):
            kubectl("apply", "-f", "-", data=json.dumps(document))

        def resource(kind, name, **fields):
            return {
                "apiVersion": "v1",
                "kind": kind,
                "metadata": {"name": name},
                **fields,
            }

        apply(
            resource(
                "Secret",
                "smoke-tls",
                stringData={
                    name: (directory / name).read_text()
                    for name in ("tls.crt", "tls.key")
                },
            )
        )
        apply(
            resource(
                "ConfigMap",
                "smoke-ca",
                data={"ca.pem": (directory / "ca.pem").read_text()},
            )
        )
        apply(
            resource(
                "ConfigMap",
                "smoke-fixture",
                data={"fixtures.py": (HERE / "fixtures.py").read_text()},
            )
        )
        apply(
            resource(
                "Secret",
                "smoke-vault-token",
                stringData={"token": "disposable-vault-root-token"},
            )
        )
        realm = {
            "realm": "shim",
            "enabled": True,
            "sslRequired": "all",
            "groups": [{"name": "owners"}],
            "clients": [
                {
                    "clientId": "shim",
                    "secret": "disposable-client-secret",
                    "enabled": True,
                    "publicClient": False,
                    "standardFlowEnabled": True,
                    "redirectUris": ["https://fixture:8443/api/v1/auth/callback"],
                    "attributes": {
                        "pkce.code.challenge.method": "S256",
                        "post.logout.redirect.uris": "https://fixture:8443/login",
                    },
                    "protocolMappers": [
                        {
                            "name": "groups",
                            "protocol": "openid-connect",
                            "protocolMapper": "oidc-group-membership-mapper",
                            "config": {
                                "claim.name": "groups",
                                "full.path": "true",
                                "id.token.claim": "true",
                                "access.token.claim": "true",
                                "userinfo.token.claim": "true",
                            },
                        }
                    ],
                }
            ],
            "users": [
                {
                    "username": "pilot",
                    "email": "pilot@example.com",
                    "emailVerified": True,
                    "enabled": True,
                    "firstName": "Pilot",
                    "lastName": "Test",
                    "groups": ["/owners"],
                    "credentials": [
                        {
                            "type": "password",
                            "value": "disposable-pilot-password",
                            "temporary": False,
                        }
                    ],
                }
            ],
        }
        apply(
            resource("ConfigMap", "smoke-realm", data={"realm.json": json.dumps(realm)})
        )

        def fixture(
            name, image, ports, command_parts, env=None, mounts=None, volumes=None
        ):
            container = {
                "name": name,
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": command_parts,
                "ports": [{"containerPort": port} for port in ports],
                "env": [
                    {"name": key, "value": value} for key, value in (env or {}).items()
                ],
                "volumeMounts": mounts or [],
                "readinessProbe": {"tcpSocket": {"port": ports[0]}, "periodSeconds": 3},
            }
            apply(
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": name},
                    "spec": {
                        "selector": {"matchLabels": {"fixture": name}},
                        "template": {
                            "metadata": {"labels": {"fixture": name}},
                            "spec": {
                                "automountServiceAccountToken": False,
                                "containers": [container],
                                "volumes": volumes or [],
                            },
                        },
                    },
                }
            )
            apply(
                resource(
                    "Service",
                    name,
                    spec={
                        "selector": {"fixture": name},
                        "ports": [
                            {
                                "name": "port-" + str(port),
                                "port": port,
                                "targetPort": port,
                            }
                            for port in ports
                        ],
                    },
                )
            )

        tls_mount = {"name": "tls", "mountPath": "/tls", "readOnly": True}
        tls_volume = {"name": "tls", "secret": {"secretName": "smoke-tls"}}
        fixture(
            "keycloak",
            runtime_images[KEYCLOAK],
            [8443],
            [
                "/opt/keycloak/bin/kc.sh",
                "start-dev",
                "--import-realm",
                "--hostname=https://keycloak:8443",
                "--https-certificate-file=/tls/tls.crt",
                "--https-certificate-key-file=/tls/tls.key",
            ],
            mounts=[
                tls_mount,
                {"name": "realm", "mountPath": "/opt/keycloak/data/import"},
            ],
            volumes=[
                tls_volume,
                {"name": "realm", "configMap": {"name": "smoke-realm"}},
            ],
        )
        fixture(
            "vault",
            runtime_images[VAULT],
            [8200],
            [
                "vault",
                "server",
                "-dev",
                "-dev-listen-address=0.0.0.0:8200",
                "-dev-root-token-id=disposable-vault-root-token",
            ],
            env={"SKIP_SETCAP": "true"},
        )
        fixture(
            "fixture",
            runtime_images[overlay],
            [8443, 8444, 8445],
            ["python", "/fixture/fixtures.py", "serve"],
            mounts=[tls_mount, {"name": "script", "mountPath": "/fixture"}],
            volumes=[
                tls_volume,
                {"name": "script", "configMap": {"name": "smoke-fixture"}},
            ],
        )
        organization = str(uuid4())
        backend = {
            "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
            "DATABASE_URL": "",
            "REDIS_URL": "redis://smoke-redis:6379/0",
            "SECRET_KEY": secrets.token_urlsafe(48),
            "ENCRYPTION_KEY": base64.urlsafe_b64encode(
                secrets.token_bytes(32)
            ).decode(),
            "SHIM_LICENSE_KEY": license_token,
            "AUTH_MODE": "oidc",
            "OIDC_ISSUER_URL": "https://keycloak:8443/realms/shim",
            "OIDC_CLIENT_ID": "shim",
            "OIDC_CLIENT_SECRET": "disposable-client-secret",
            "OIDC_REDIRECT_URI": "https://fixture:8443/api/v1/auth/callback",
            "DASHBOARD_ORIGIN": "https://fixture:8443",
            "OIDC_ORGANIZATION_ID": organization,
            "OIDC_GROUP_ROLE_MAP": json.dumps({"/owners": "owner"}),
            "SECRET_BACKEND": "vault",
            "VAULT_ADDR": "https://fixture:8444",
            "VAULT_TOKEN_FILE": "/var/run/shim-vault/token",
            "MODEL_DEPLOYMENT_ALLOWED_ORIGINS": json.dumps(["https://fixture:8445"]),
            "MODEL_DEPLOYMENT_CA_BUNDLE": "/var/run/shim-ca/ca.pem",
        }
        backend["DATABASE_URL"] = (
            f"postgresql+asyncpg://shim:{backend['POSTGRES_PASSWORD']}@smoke-postgres:5432/shim"
        )
        apply(resource("Secret", "smoke-config", stringData=backend))
        overrides = {
            "existingSecret": "smoke-config",
            "gateway": {"image": runtime_images[overlay]},
            "dashboard": {"image": runtime_images[args.dashboard_image]},
            "vault": {"tokenSecretName": "smoke-vault-token"},
            "caBundleConfigMap": "smoke-ca",
            "postgres": {
                "enabled": True,
                "storage": "1Gi",
                "image": runtime_images[values["postgres"]["image"]],
            },
            "redis": {
                "enabled": True,
                "storage": "1Gi",
                "image": runtime_images[values["redis"]["image"]],
            },
        }
        (directory / "values.json").write_text(json.dumps(overrides))
        command(
            "helm",
            "upgrade",
            "--install",
            "smoke",
            str(chart),
            "--kubeconfig",
            str(kubeconfig),
            "-f",
            str(directory / "values.json"),
            "--wait",
            "--timeout",
            "10m",
        )
        for name in (
            "gateway",
            "dashboard",
            "outbox",
            "reconciliation",
            "compliance",
            "ai-act",
        ):
            kubectl("rollout", "status", "deployment/smoke-" + name, "--timeout=180s")
        # Exercise the documented operator bootstrap, then roll out the real tenant UUID.
        organization = kubectl(
            "exec",
            "deployment/smoke-gateway",
            "--",
            "python",
            "ee/scripts/activate_plan.py",
            "--create-name",
            "Isolated chart smoke",
            "enterprise",
            capture=True,
        ).splitlines()[-1]
        backend["OIDC_ORGANIZATION_ID"] = str(UUID(organization))
        apply(resource("Secret", "smoke-config", stringData=backend))
        for name in ("gateway", "outbox", "reconciliation", "compliance", "ai-act"):
            kubectl("rollout", "restart", "deployment/smoke-" + name)
        for name in ("gateway", "outbox", "reconciliation", "compliance", "ai-act"):
            kubectl("rollout", "status", "deployment/smoke-" + name, "--timeout=180s")
        kubectl(
            "exec",
            "-i",
            "deployment/smoke-gateway",
            "--",
            "python",
            "-c",
            "import sys; from pathlib import Path; Path('/tmp/fixtures.py').write_text(sys.stdin.read())",
            data=(HERE / "fixtures.py").read_text(),
        )
        kubectl(
            "exec",
            "deployment/smoke-gateway",
            "--",
            "python",
            "/tmp/fixtures.py",
            "smoke",
        )
        (directory / "asset-audit.json").write_text(
            kubectl(
                "exec",
                "deployment/smoke-gateway",
                "--",
                "cat",
                "/tmp/shim-asset-audit.json",
                capture=True,
            )
        )
        (directory / "result.json").write_text(
            json.dumps(
                {
                    "passed": True,
                    "gateway_source_image": original_image,
                    "dashboard_image": args.dashboard_image,
                    "test_overlay_image": overlay,
                    "images": image_evidence,
                    "internet_isolation": "Node IPv4/IPv6 OUTPUT+FORWARD firewall; no upstream DNS; gateway public-IP runtime probes",
                    "production_license_unchanged": True,
                },
                indent=2,
            )
        )
        print(
            "PASS chart installation, six deployments ready, complete isolated smoke",
            flush=True,
        )
    finally:
        if kubeconfig.exists():
            result = subprocess.run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(kubeconfig),
                    "get",
                    "pods,jobs",
                    "-A",
                    "-o",
                    "wide",
                ],
                capture_output=True,
                text=True,
            )
            (directory / "resources.txt").write_text(result.stdout + result.stderr)
        if not args.keep:
            command(
                "kind",
                "delete",
                "cluster",
                "--name",
                args.cluster,
                "--kubeconfig",
                str(kubeconfig),
            )
            command("docker", "network", "rm", network)
        print(
            f"Test-only image {overlay}; never publish it. Remove local test material with trash {directory} after review."
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--dashboard-image", required=True)
    parser.add_argument(
        "--node-image",
        default="kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
    )
    parser.add_argument("--chart", type=Path, default=HERE.parent / "chart")
    parser.add_argument("--cluster", default="shim-on-prem-smoke")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument(
        "--reuse-empty-cluster",
        action="store_true",
        help="Continue a failed image preload only; refuses application workloads",
    )
    args = parser.parse_args()
    if any(
        any(char.isspace() for char in image) or image.startswith("-")
        for image in (args.gateway_image, args.dashboard_image, args.node_image)
    ):
        parser.error("Image references must be single Docker image names")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", args.cluster):
        parser.error("Use a lowercase disposable cluster name, at most 31 characters")
    run(args)


if __name__ == "__main__":
    main()
