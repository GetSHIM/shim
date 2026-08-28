from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPARISON_SNAPSHOTS = (
    ("main", "87994cc60dff33cdf3e34233b527b69c0c5470bb"),
    (
        "feature/openai-compatible-cli-agents",
        "575326e6eab9a57a8e9be7039620a30ca00ae9fe",
    ),
)


def _working_product_files() -> set[str]:
    output = subprocess.check_output(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        cwd=ROOT,
    )
    return {
        path
        for raw in output.split(b"\0")
        if raw and (path := raw.decode()) and (ROOT / path).is_file()
    }


def _resolve_ref(candidate: str) -> str | None:
    for ref in (candidate, f"origin/{candidate}"):
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", ref],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return None
        if result.returncode == 0:
            return ref
    return None


def _ref_blob_hashes(ref: str) -> set[str]:
    output = subprocess.check_output(
        ["git", "ls-tree", "-r", "--format=%(objectname)", ref],
        cwd=ROOT,
        text=True,
    )
    return set(output.splitlines())


def _working_blob_hash(path: str) -> str:
    return subprocess.check_output(
        ["git", "hash-object", "--", path],
        cwd=ROOT,
        text=True,
    ).strip()


def _ref_text(ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def test_sdk_native_gateway_deletion_manifest_is_enforced() -> None:
    removed = {
        "src/shim/gateway/providers",
        "src/shim/gateway/api/chat_adapter.py",
        "src/shim/gateway/api/responses_adapter.py",
        "src/shim/gateway/api/response_renderers.py",
        "src/shim/gateway/integrations",
        "src/shim/gateway/contracts/provider.py",
        "src/shim/gateway/contracts/streaming.py",
        "src/shim/gateway/pipeline/routing.py",
        "src/shim/gateway/streaming/events.py",
        "src/shim/gateway/facade.py",
        "src/shim/gateway/pipeline/cache.py",
        "ee/src/shim_enterprise/cache/semantic.py",
    }

    assert all(not (ROOT / path).exists() for path in removed)
    assert (ROOT / "ee/src/shim_enterprise/privacy/chain_store.py").is_file()
    pipeline = ROOT / "src/shim/gateway/pipeline"
    assert all(
        (pipeline / name).is_file()
        for name in (
            "anthropic_execution.py",
            "google_execution.py",
            "openai_execution.py",
            "provider_execution.py",
        )
    )
    shared_execution = (pipeline / "provider_execution.py").read_text()
    assert "OpenAIExecution" not in shared_execution
    assert "import openai" not in shared_execution
    assert '"openai"' not in shared_execution


@pytest.mark.parametrize(("label", "snapshot"), COMPARISON_SNAPSHOTS)
def test_no_working_blob_is_identical_to_comparison_branch(
    label: str,
    snapshot: str,
) -> None:
    ref = _resolve_ref(snapshot)
    if ref is None:
        pytest.skip(f"comparison snapshot is unavailable: {label}")
    retired_hashes = _ref_blob_hashes(ref)
    identical = {
        path
        for path in _working_product_files()
        if _working_blob_hash(path) in retired_hashes
    }

    assert identical == set()


@pytest.mark.parametrize(("label", "snapshot"), COMPARISON_SNAPSHOTS)
def test_application_sources_are_fresh_implementations(
    label: str,
    snapshot: str,
) -> None:
    ref = _resolve_ref(snapshot)
    if ref is None:
        pytest.skip(f"comparison snapshot is unavailable: {label}")
    offenders: dict[str, float] = {}
    for path in sorted(_working_product_files()):
        if not path.endswith(".py") or not path.startswith(
            ("ee/src/shim_enterprise/", "src/shim/")
        ):
            continue
        comparison_path = path
        if path.startswith("ee/src/shim_enterprise/"):
            enterprise_path = path.removeprefix("ee/src/shim_enterprise/")
            comparison_path = {
                "application.py": "app/main.py",
                "workers/ai_act.py": "app/ai_act/worker.py",
                "workers/compliance.py": "app/compliance/worker.py",
                "workers/outbox.py": "app/outbox/worker.py",
                "workers/reconciliation.py": "app/billing/reconciliation.py",
            }.get(enterprise_path, f"app/{enterprise_path}")
        retired = _ref_text(ref, comparison_path)
        if retired is None:
            continue
        current = (ROOT / path).read_text(encoding="utf-8")
        similarity = difflib.SequenceMatcher(
            None,
            retired.splitlines(),
            current.splitlines(),
            autojunk=False,
        ).ratio()
        if similarity >= 0.50:
            offenders[path] = round(similarity, 3)

    assert offenders == {}


def test_openapi_profiles_have_typed_management_and_sdk_native_inference() -> None:
    community_schema = json.loads(
        (ROOT / "openapi/community.json").read_text(encoding="utf-8")
    )
    enterprise_schema = json.loads(
        (ROOT / "ee/openapi/enterprise.json").read_text(encoding="utf-8")
    )

    security_schemes = community_schema["components"]["securitySchemes"]
    assert security_schemes["ShimAPIKey"]["name"] == "x-shim-key"
    assert security_schemes["AnthropicAPIKey"]["name"] == "x-api-key"
    assert security_schemes == enterprise_schema["components"]["securitySchemes"]

    expected = {
        "/api/v1/management/billing/breakdown": "BillingBreakdownView",
        "/api/v1/management/billing/usage": "BillingUsageView",
        "/api/v1/management/cost/budgets/evaluate": "BudgetEvaluationView",
        "/api/v1/management/overview": "OverviewDashboardView",
        "/api/v1/management/requests": "RequestActivityPage",
    }
    for path, component in expected.items():
        operation = next(iter(enterprise_schema["paths"][path].values()))
        response_schema = operation["responses"]["200"]["content"]["application/json"][
            "schema"
        ]
        assert response_schema == {"$ref": f"#/components/schemas/{component}"}

    models_schema = community_schema["paths"]["/v1/models"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    assert {item["$ref"] for item in models_schema["anyOf"]} == {
        "#/components/schemas/AnthropicModelListView",
        "#/components/schemas/CodexModelListView",
        "#/components/schemas/ModelListView",
    }
    model_parameters = community_schema["paths"]["/v1/models"]["get"]["parameters"]
    assert any(
        parameter["name"] == "anthropic-version" and parameter["in"] == "header"
        for parameter in model_parameters
    )

    retrieve_model_schema = community_schema["paths"]["/v1/models/{model_id}"]["get"][
        "responses"
    ]["200"]["content"]["application/json"]["schema"]
    assert {item["$ref"] for item in retrieve_model_schema["anyOf"]} == {
        "#/components/schemas/AnthropicModelRecordView",
        "#/components/schemas/ModelRecordView",
    }
    for path, status_code in (
        ("/v1/models", "400"),
        ("/v1/models/{model_id}", "404"),
    ):
        error_schema = community_schema["paths"][path]["get"]["responses"][status_code][
            "content"
        ]["application/json"]["schema"]
        assert {item["$ref"] for item in error_schema["anyOf"]} == {
            "#/components/schemas/AnthropicErrorResponse",
            "#/components/schemas/OpenAIErrorResponse",
        }

    request_components = {
        "/v1/messages": "MessagesRequest",
        "/v1beta/models/{model}:generateContent": "GenerateContentRequest",
        "/v1beta/models/{model}:streamGenerateContent": "GenerateContentRequest",
    }
    for path, component in request_components.items():
        request_schema = community_schema["paths"][path]["post"]["requestBody"][
            "content"
        ]["application/json"]["schema"]
        assert request_schema == {"$ref": f"#/components/schemas/{component}"}

    for path in (
        "/v1/chat/completions",
        "/v1/responses",
        "/v1/messages",
        "/v1beta/models/{model}:streamGenerateContent",
    ):
        content = community_schema["paths"][path]["post"]["responses"]["200"]["content"]
        assert content["text/event-stream"]["schema"] == {"type": "string"}
        assert content["application/json"]["schema"] == {}

    provider_errors = {
        "/v1/chat/completions": "OpenAIErrorResponse",
        "/v1/responses": "OpenAIErrorResponse",
        "/v1/messages": "AnthropicErrorResponse",
    }
    for path, component in provider_errors.items():
        response_schema = community_schema["paths"][path]["post"]["responses"]["429"][
            "content"
        ]["application/json"]["schema"]
        assert response_schema == {"$ref": f"#/components/schemas/{component}"}

    google_json = community_schema["paths"]["/v1beta/models/{model}:generateContent"][
        "post"
    ]
    assert google_json["responses"]["200"]["content"] == {
        "application/json": {"schema": {}}
    }

    google_stream_parameters = community_schema["paths"][
        "/v1beta/models/{model}:streamGenerateContent"
    ]["post"]["parameters"]
    alt = next(item for item in google_stream_parameters if item["name"] == "alt")
    assert alt["schema"]["const"] == "sse"

    report_content = {
        "application/pdf": {"schema": {"format": "binary", "type": "string"}},
        "text/csv": {"schema": {"format": "binary", "type": "string"}},
    }
    for path, method in (
        ("/api/v1/compliance/reports/audit", "post"),
        ("/api/v1/compliance/reports/kvkk", "post"),
        ("/api/v1/management/billing/export", "get"),
    ):
        response = enterprise_schema["paths"][path][method]["responses"]["200"]
        assert response["content"] == report_content
        assert response["headers"]["Content-Disposition"]["schema"] == {
            "type": "string"
        }

    request_export = enterprise_schema["paths"]["/api/v1/management/requests/export"][
        "get"
    ]["responses"]["200"]
    assert request_export["content"] == {"text/csv": report_content["text/csv"]}
    assert request_export["headers"]["Content-Disposition"]["schema"] == {
        "type": "string"
    }

    components = community_schema["components"]["schemas"]
    assert "MessagesRequest" in components
    assert "GenerateContentRequest" in components
    assert "ResponsesRequest" in components
    assert "ChatRequest" in components
    assert "ResponsesResponse" not in components
    assert "ChatCompletionResponse" not in components

    provider_paths = (
        "/v1/chat/completions",
        "/v1/messages",
        "/v1/models",
        "/v1/models/{model_id}",
        "/v1/responses",
        "/v1beta/models/{model}:generateContent",
        "/v1beta/models/{model}:streamGenerateContent",
    )
    assert {path: community_schema["paths"][path] for path in provider_paths} == {
        path: enterprise_schema["paths"][path] for path in provider_paths
    }
    shared_components = components.keys() - {
        "CommunityScanResponse",
        "ScanEntity",
    }
    enterprise_components = enterprise_schema["components"]["schemas"]
    assert shared_components <= enterprise_components.keys()
    assert {name: components[name] for name in shared_components} == {
        name: enterprise_components[name] for name in shared_components
    }


def test_application_tree_has_no_retired_implementation_patterns() -> None:
    patterns = {
        "retired module import": re.compile(
            r"shim_enterprise\."
            r"(?:services\.providers|gateway\.(?:scan|persistence|outbox))"
        ),
        "compatibility implementation": re.compile(
            r"\b(?:openai_compat|rollback_delegate|dual_writer|dual_write|"
            r"bridge_reader|cutover_flag)\b",
            re.IGNORECASE,
        ),
        "retired account schema": re.compile(
            r"\b(?:password_hash|hashed_password|is_superuser|stripe_customer|"
            r"subscription_status)\b",
            re.IGNORECASE,
        ),
        "global provider credential": re.compile(
            r"\b(?:OPENAI|ANTHROPIC|GOOGLE)_API_KEY\b"
        ),
    }
    offenders: dict[str, list[str]] = {}
    sources = [
        *sorted((ROOT / "ee/alembic").rglob("*.py")),
        *sorted((ROOT / "ee/src/shim_enterprise").rglob("*.py")),
        *sorted((ROOT / "src/shim").rglob("*.py")),
    ]
    for source in sources:
        text = source.read_text()
        matched = [
            label
            for label, pattern in patterns.items()
            if pattern.search(text)
            and not (
                label == "global provider credential"
                and source == ROOT / "src/shim/secrets/credentials.py"
            )
        ]
        if matched:
            offenders[source.relative_to(ROOT).as_posix()] = matched

    assert offenders == {}


def test_core_resource_boundaries_depend_only_on_structural_ports() -> None:
    middleware = (ROOT / "src/shim/core/middleware.py").read_text()
    circuit_breaker = (ROOT / "src/shim/core/circuit_breaker.py").read_text()

    assert "shim_enterprise.billing" not in middleware
    assert "shim_enterprise.cache" not in circuit_breaker


def test_gateway_stages_do_not_resolve_process_cache_singletons() -> None:
    offenders = {
        source.relative_to(ROOT).as_posix()
        for gateway_root in (
            ROOT / "ee/src/shim_enterprise/gateway",
            ROOT / "src/shim/gateway",
        )
        for source in sorted(gateway_root.rglob("*.py"))
        if ".get_instance(" in source.read_text()
    }

    assert offenders == set()


@pytest.mark.parametrize(
    "compose_name", ("docker-compose.yml", "docker-compose.prod.yml")
)
def test_compose_separates_migrations_and_reconciliation_from_gateway(
    compose_name: str,
) -> None:
    compose = yaml.safe_load((ROOT / compose_name).read_text())
    services = compose["services"]
    gateway = services["gateway-api"]
    migration = services["migrate"]
    worker = services["reconciliation-worker"]

    assert worker["command"] == [
        "python",
        "-m",
        "shim_enterprise.workers.reconciliation",
    ]
    assert "profiles" not in worker
    assert worker["depends_on"] == {"gateway-api": {"condition": "service_healthy"}}
    assert migration["command"] == [
        "alembic",
        "-c",
        "ee/alembic.ini",
        "upgrade",
        "head",
    ]
    assert gateway["depends_on"]["migrate"] == {
        "condition": "service_completed_successfully"
    }
    assert "command" not in gateway


def test_production_compose_pins_production_secret_policy() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())

    for service in compose["services"].values():
        environment = service["environment"]
        assert environment["ENVIRONMENT"] == "production"
        assert environment["SECRET_BACKEND"] == "gcp_secret_manager"
        assert environment["GOOGLE_CLOUD_PROJECT"] == (
            "${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
        )


def test_runtime_image_does_not_run_migrations_on_container_start() -> None:
    dockerfile = (ROOT / "ee/Dockerfile").read_text()
    command = next(line for line in dockerfile.splitlines() if line.startswith("CMD "))

    assert command == (
        'CMD ["uvicorn", '
        '"shim_enterprise.application:create_enterprise_app", "--factory", '
        '"--host", "0.0.0.0", "--port", "8000", "--workers", "1"]'
    )


def test_enterprise_application_is_factory_only() -> None:
    application = (ROOT / "ee/src/shim_enterprise/application.py").read_text()

    assert "\napp = create_enterprise_app()" not in application


def test_mixed_license_boundary_is_exact() -> None:
    community = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    enterprise = tomllib.loads((ROOT / "ee/pyproject.toml").read_text())["project"]

    assert community["license"] == "Apache-2.0"
    assert community["license-files"] == ["LICENSE", "NOTICE"]
    assert enterprise["license"] == "Elastic-2.0"
    assert enterprise["license-files"] == ["LICENSE", "NOTICE"]
    expected_hashes = {
        "LICENSE": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        "NOTICE": "2a5a107bb6c52521719738de19c401ffc17d67b35d1d8ca24694a18134739eac",
        "ee/LICENSE": "48255018b41fc0e965b1115af7e6779bc218bb8a6747d561da800d5022622aa2",
        "ee/NOTICE": "4e0f381df25ed1544459e600db6d4a3a3900bd2a5048e9e5477ea168d5a6ce07",
    }
    assert {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in expected_hashes
    } == expected_hashes


def test_docker_build_contexts_are_exactly_allowlisted() -> None:
    expected = {
        "Dockerfile.dockerignore": (
            "**",
            "!README.md",
            "!LICENSE",
            "!NOTICE",
            "!pyproject.toml",
            "!uv.lock",
            "!src/",
            "!src/**",
            "!ee/",
            "!ee/pyproject.toml",
            "**/__pycache__/",
            "**/*.py[cod]",
        ),
        "ee/Dockerfile.dockerignore": (
            "**",
            "!README.md",
            "!LICENSE",
            "!NOTICE",
            "!pyproject.toml",
            "!uv.lock",
            "!src/",
            "!src/**",
            "!ee/",
            "!ee/LICENSE",
            "!ee/NOTICE",
            "!ee/pyproject.toml",
            "!ee/src/",
            "!ee/src/**",
            "!ee/alembic.ini",
            "!ee/alembic/",
            "!ee/alembic/**",
            "!ee/scripts/",
            "!ee/scripts/**",
            "**/__pycache__/",
            "**/*.py[cod]",
        ),
    }

    for path, lines in expected.items():
        assert (ROOT / path).read_text().splitlines() == list(lines)


def test_cloud_build_deploys_migrations_and_standalone_workers() -> None:
    deployment_path = ROOT / "cloudbuild.yaml"
    deployment_text = deployment_path.read_text()
    deployment = yaml.safe_load(deployment_text)
    steps = {step.get("id"): step for step in deployment["steps"]}
    substitutions = deployment["substitutions"]

    assert "GATEWAY_OUTBOX_WORKER_ENABLED" not in deployment_text
    assert all("@sha256:" in step["name"] for step in deployment["steps"])
    assert {
        "validate-deployment",
        "build-image",
        "acquire-deployment-lock",
        "deploy-migration",
        "run-migration",
        "deploy-gateway",
        "deploy-outbox-worker",
        "deploy-reconciliation-worker",
        "deploy-compliance-worker",
        "deploy-ai-act-worker",
        "verify-gateway",
        "promote-release",
    } <= steps.keys()
    assert "--command=uvicorn" in steps["deploy-gateway"]["args"]
    assert "--no-traffic" in steps["deploy-gateway"]["args"]
    assert "--deploy-health-check" in steps["deploy-gateway"]["args"]
    assert all(
        not argument.startswith("--tag=")
        for argument in steps["deploy-gateway"]["args"]
    )
    assert "--revision-suffix=rel-$SHORT_SHA" in steps["deploy-gateway"]["args"]
    assert "--args=-c,ee/alembic.ini,upgrade,head" in steps["deploy-migration"]["args"]
    expected_workers = {
        "deploy-outbox-worker": "--args=-m,shim_enterprise.workers.outbox",
        "deploy-reconciliation-worker": (
            "--args=-m,shim_enterprise.workers.reconciliation"
        ),
        "deploy-compliance-worker": "--args=-m,shim_enterprise.workers.compliance",
        "deploy-ai-act-worker": "--args=-m,shim_enterprise.workers.ai_act",
    }
    for step_id, command in expected_workers.items():
        assert "worker-pools" in steps[step_id]["args"]
        assert "--instances=${_WORKER_INSTANCES}" in steps[step_id]["args"]
        assert "--no-promote" in steps[step_id]["args"]
        assert "--revision-suffix=rel-$SHORT_SHA" in steps[step_id]["args"]
        assert command in steps[step_id]["args"]

    assert substitutions["_DEPLOY_PROJECT_ID"] == "shim-prod"
    assert substitutions["_DEPLOY_TRIGGER_ID"] == (
        "3d769864-29a7-46f0-a2ec-73d488e3a5a5"
    )
    assert substitutions["_DEPLOY_LOCK_URI"] == (
        "gs://shim-prod_europe-west3_cloudbuild/locks/shim-production"
    )
    assert substitutions["_RESOURCE_PREFIX"] == "shim"
    assert substitutions["_ARTIFACT_REPOSITORY"] == "shim"
    assert substitutions["_SECRET_PREFIX"] == "shim"
    assert substitutions["_RUNTIME_SERVICE_ACCOUNT"] == (
        "shim-runtime@shim-prod.iam.gserviceaccount.com"
    )
    assert substitutions["_MIGRATION_SERVICE_ACCOUNT"] == (
        "shim-migrate@shim-prod.iam.gserviceaccount.com"
    )
    assert deployment["serviceAccount"] == (
        "projects/shim-prod/serviceAccounts/"
        "shim-build@shim-prod.iam.gserviceaccount.com"
    )
    assert substitutions["_WORKER_INSTANCES"] == "1"
    assert substitutions["_MIN_INSTANCES"] == "1"
    assert substitutions["_MAX_INSTANCES"] == "10"
    assert substitutions["_DATABASE_POOL_SIZE"] == "2"
    assert substitutions["_DATABASE_MAX_OVERFLOW"] == "1"
    assert "_REDIS_URL" not in substitutions
    assert substitutions["_FRONTEND_ORIGINS"].split(",") == [
        "https://shim-phi.vercel.app",
        "https://getshim.tech",
        "https://www.getshim.tech",
    ]
    validation_environment = steps["validate-deployment"]["env"]
    assert "ACTUAL_PROJECT_ID=$PROJECT_ID" in validation_environment
    assert "BUILD_ID=$BUILD_ID" in validation_environment
    assert "DEPLOY_LOCK_URI=${_DEPLOY_LOCK_URI}" in validation_environment
    assert "DEPLOY_PROJECT_ID=${_DEPLOY_PROJECT_ID}" in validation_environment
    assert "DEPLOY_TRIGGER_ID=${_DEPLOY_TRIGGER_ID}" in validation_environment
    assert "IMAGE_TAG=$COMMIT_SHA" in validation_environment
    assert "MAX_INSTANCES=${_MAX_INSTANCES}" in validation_environment
    assert "SHORT_SHA=$SHORT_SHA" in validation_environment
    assert "WORKER_INSTANCES=${_WORKER_INSTANCES}" in validation_environment
    validation_script = steps["validate-deployment"]["args"][-1].replace("$$", "$")
    validation_values = {
        "ACTUAL_PROJECT_ID": "project",
        "BUILD_ID": "00000000-0000-0000-0000-000000000000",
        "DEPLOY_LOCK_URI": "gs://bucket/lock",
        "DEPLOY_PROJECT_ID": "project",
        "DEPLOY_TRIGGER_ID": "11111111-1111-1111-1111-111111111111",
        "FRONTEND_ORIGINS": "https://example.com",
        "IMAGE_TAG": "a" * 40,
        "MAX_INSTANCES": "10",
        "SHORT_SHA": "a" * 7,
    }
    for worker_instances, succeeds in (
        ("1", True),
        ("12", True),
        ("", False),
        ("0", False),
        ("-1", False),
        ("invalid", False),
    ):
        result = subprocess.run(
            ["bash", "-ceu", validation_script],
            env=validation_values | {"WORKER_INSTANCES": worker_instances},
            check=False,
            capture_output=True,
            text=True,
        )
        assert (result.returncode == 0) is succeeds
    for max_instances, succeeds in (
        ("1", True),
        ("10", True),
        ("", False),
        ("0", False),
        ("invalid", False),
    ):
        result = subprocess.run(
            ["bash", "-ceu", validation_script],
            env=validation_values
            | {"MAX_INSTANCES": max_instances, "WORKER_INSTANCES": "1"},
            check=False,
            capture_output=True,
            text=True,
        )
        assert (result.returncode == 0) is succeeds
    for image_tag, succeeds in (
        ("a" * 40, True),
        ("a" * 39, False),
        ("g" * 40, False),
        ("", False),
    ):
        result = subprocess.run(
            ["bash", "-ceu", validation_script],
            env=validation_values | {"IMAGE_TAG": image_tag, "WORKER_INSTANCES": "1"},
            check=False,
            capture_output=True,
            text=True,
        )
        assert (result.returncode == 0) is succeeds
    assert "10.156.0.3" not in deployment_text
    assert "--vpc-connector=" not in deployment_text
    assert "europe-west3-docker.pkg.dev/$PROJECT_ID/shim/gateway" not in deployment_text
    assert "${_RESOURCE_PREFIX}-migrate" in steps["deploy-migration"]["args"]
    assert "${_RESOURCE_PREFIX}-gateway" in steps["deploy-gateway"]["args"]
    gateway_environment = next(
        argument
        for argument in steps["deploy-gateway"]["args"]
        if argument.startswith("--set-env-vars=")
    )
    assert any(
        argument.startswith(
            "--set-secrets=DATABASE_URL=${_SECRET_PREFIX}-database-url:1,"
        )
        for argument in steps["deploy-gateway"]["args"]
    )
    assert "REDIS_URL=" not in gateway_environment
    assert "BACKEND_CORS_ORIGINS=${_FRONTEND_ORIGINS}" in gateway_environment
    assert (
        "--service-account=${_MIGRATION_SERVICE_ACCOUNT}"
        in steps["deploy-migration"]["args"]
    )
    assert any(
        argument.startswith(
            "--set-secrets=DATABASE_URL=${_SECRET_PREFIX}-migration-database-url:1,"
        )
        for argument in steps["deploy-migration"]["args"]
    )
    for step_id in ("deploy-migration", "deploy-gateway", *expected_workers):
        args = steps[step_id]["args"]
        if step_id != "deploy-migration":
            assert "--service-account=${_RUNTIME_SERVICE_ACCOUNT}" in args
        assert "--network=${_VPC_NETWORK}" in steps[step_id]["args"]
        assert "--subnet=${_VPC_SUBNET}" in steps[step_id]["args"]
        assert "--vpc-egress=private-ranges-only" in steps[step_id]["args"]
        secrets = next(
            argument for argument in args if argument.startswith("--set-secrets=")
        )
        assert "REDIS_URL=${_SECRET_PREFIX}-redis-url:1" in secrets
        environment = next(
            argument for argument in args if argument.startswith("--set-env-vars=")
        )
        assert "REDIS_URL=" not in environment
        assert "DATABASE_POOL_SIZE=${_DATABASE_POOL_SIZE}" in environment
        assert "DATABASE_MAX_OVERFLOW=${_DATABASE_MAX_OVERFLOW}" in environment

    assert "--timeout=600s" in steps["deploy-gateway"]["args"]
    assert "--max=${_MAX_INSTANCES}" in steps["deploy-gateway"]["args"]
    for step_id in (
        "deploy-migration",
        "run-migration",
        "deploy-gateway",
        *expected_workers,
    ):
        assert "--project=${_DEPLOY_PROJECT_ID}" in steps[step_id]["args"]
    configured_secrets = {
        name
        for step_id in ("deploy-migration", "deploy-gateway", *expected_workers)
        for argument in steps[step_id]["args"]
        if argument.startswith("--set-secrets=")
        for name, _, _ in (
            secret.partition("=")
            for secret in argument.removeprefix("--set-secrets=").split(",")
        )
    }
    assert not {"LEMON_SQUEEZY_SIGNING_SECRET", "RESEND_API_KEY"} & configured_secrets
    migration_secrets = next(
        argument
        for argument in steps["deploy-migration"]["args"]
        if argument.startswith("--set-secrets=")
    )
    assert "SENTRY_DSN" not in migration_secrets
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in migration_secrets
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in migration_secrets
    for step_id in ("deploy-gateway", *expected_workers):
        args = steps[step_id]["args"]
        secrets = next(
            argument for argument in args if argument.startswith("--set-secrets=")
        )
        assert "SENTRY_DSN=${_SECRET_PREFIX}-sentry-dsn:1" in secrets
        assert (
            "OTEL_EXPORTER_OTLP_ENDPOINT="
            "${_SECRET_PREFIX}-otel-exporter-otlp-endpoint:1" in secrets
        )
        assert (
            "OTEL_EXPORTER_OTLP_HEADERS="
            "${_SECRET_PREFIX}-otel-exporter-otlp-headers:1" in secrets
        )
        environment = next(
            argument for argument in args if argument.startswith("--set-env-vars=")
        )
        assert "OTEL_EXPORTER_OTLP_" not in environment
    migration_environment = next(
        argument
        for argument in steps["deploy-migration"]["args"]
        if argument.startswith("--set-env-vars=")
    )
    assert "SENTRY_DSN" not in migration_environment
    assert "OTEL_" not in migration_environment
    assert {
        "_OTEL_EXPORTER_OTLP_ENDPOINT",
        "_OTEL_EXPORTER_OTLP_HEADERS",
    }.isdisjoint(substitutions)
    secret_versions = {
        version
        for step_id in ("deploy-migration", "deploy-gateway", *expected_workers)
        for argument in steps[step_id]["args"]
        if argument.startswith("--set-secrets=")
        for _, _, version in (
            secret.rpartition(":")
            for secret in argument.removeprefix("--set-secrets=").split(",")
        )
    }
    assert secret_versions == {"1"}

    image_ref = (
        "${_REGION}-docker.pkg.dev/$PROJECT_ID/"
        "${_ARTIFACT_REPOSITORY}/${_IMAGE_NAME}:$COMMIT_SHA"
    )
    assert f"--destination={image_ref}" in steps["build-image"]["args"]
    for step_id in ("deploy-migration", "deploy-gateway", *expected_workers):
        assert f"--image={image_ref}" in steps[step_id]["args"]

    assert any(
        "ENCRYPTION_KEY=${_SECRET_PREFIX}-encryption-key:1" in argument
        for argument in steps["deploy-gateway"]["args"]
    )
    step_ids = [step.get("id") for step in deployment["steps"]]
    lock_index = step_ids.index("acquire-deployment-lock")
    run_migration_index = step_ids.index("run-migration")
    candidate_step_ids = ("deploy-gateway", *expected_workers)
    assert step_ids.index("build-image") < lock_index
    assert lock_index < step_ids.index("deploy-migration") < run_migration_index
    assert all(
        run_migration_index < step_ids.index(step_id) for step_id in candidate_step_ids
    )
    assert step_ids.index("deploy-gateway") < step_ids.index("verify-gateway")
    assert step_ids.index("verify-gateway") < step_ids.index("deploy-outbox-worker")
    assert max(
        step_ids.index(step_id) for step_id in candidate_step_ids
    ) < step_ids.index("promote-release")
    assert step_ids[-1] == "promote-release"
    lock_script = steps["acquire-deployment-lock"]["args"][-1]
    promotion_script = steps["promote-release"]["args"][-1]
    verification_script = steps["verify-gateway"]["args"][-1]
    assert "workers=(outbox reconciliation compliance ai-act)" in promotion_script
    assert "worker-pools update-instance-split" in promotion_script
    assert "services update-traffic" in promotion_script
    assert "--to-latest" not in promotion_script
    assert '--to-revisions="$$candidate=100"' in promotion_script
    assert '--to-revisions="$$candidate_gateway=100"' in promotion_script
    assert "--if-generation-match=0" in lock_script
    assert "SUCCESS|FAILURE|INTERNAL_ERROR|TIMEOUT|CANCELLED|EXPIRED" in lock_script
    assert "status=(QUEUED OR PENDING OR WORKING OR SUCCESS)" in lock_script
    assert "deployment lock ownership verification failed" in lock_script
    assert "deployment-lock-generation" in lock_script
    assert '--if-generation-match="$$lock_generation"' in promotion_script
    assert "buildTriggerId:$$DEPLOY_TRIGGER_ID" in promotion_script
    assert "a newer main deployment superseded this build" in promotion_script
    assert "restore_workers" in promotion_script
    assert "restore_gateway" in promotion_script
    assert 'attempted_workers+=("$$worker")' in promotion_script
    assert "gateway_attempted=true" in promotion_script
    assert "cleanup_rollout" in promotion_script
    assert "trap cleanup_rollout EXIT" in promotion_script
    assert "rollout_complete=true" in promotion_script
    assert "skipped stale restore" in promotion_script
    assert "resource.labels.revision_name" in promotion_script
    assert "severity>=ERROR" in promotion_script
    assert "jsonPayload.level" in promotion_script
    assert 'jsonPayload.message:"errors=0"' in promotion_script
    for marker in (
        "Outbox worker started",
        "Gateway reconciliation worker started",
        "Compliance sweep completed",
        "Audit maintenance completed",
    ):
        assert marker in promotion_script
    for script in (verification_script, promotion_script):
        assert '"status": "ok"' in script
        assert '"database": "connected"' in script
        assert '"redis": "connected"' in script
        assert "/health" in script
    assert 'route.get("tag") == tag' in verification_script
    assert "--update-tags=" in verification_script
    assert "--remove-tags=" in verification_script
    assert "trap remove_release_tag EXIT" in verification_script
    assert "trap - EXIT" in verification_script
    assert deployment["timeout"] == "3600s"
    for step_id in (
        "acquire-deployment-lock",
        "verify-gateway",
        "promote-release",
    ):
        result = subprocess.run(
            ["bash", "-n"],
            input=steps[step_id]["args"][-1].replace("$$", "$"),
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    reconciliation_args = steps["deploy-reconciliation-worker"]["args"]
    assert any(
        argument.startswith(
            "--set-secrets=DATABASE_URL=${_SECRET_PREFIX}-database-url:1,"
        )
        for argument in reconciliation_args
    )
    reconciliation_environment = next(
        argument
        for argument in reconciliation_args
        if argument.startswith("--set-env-vars=")
    )
    assert "ENVIRONMENT=production" in reconciliation_environment
    assert "SECRET_BACKEND=gcp_secret_manager" in reconciliation_environment
    assert (
        "OTEL_SERVICE_NAME=${_RESOURCE_PREFIX}-reconciliation-worker"
        in reconciliation_environment
    )


def test_cloud_build_restores_a_worker_after_a_lost_update_response(
    tmp_path: Path,
) -> None:
    deployment = yaml.safe_load((ROOT / "cloudbuild.yaml").read_text())
    promotion = next(
        step for step in deployment["steps"] if step.get("id") == "promote-release"
    )["args"][-1].replace("$$", "$")
    lock_generation = tmp_path / "deployment-lock-generation"
    lock_generation.write_text("123\n")
    promotion = promotion.replace(
        "/workspace/deployment-lock-generation",
        str(lock_generation),
    )

    command_log = tmp_path / "gcloud.log"
    worker_state = tmp_path / "worker.state"
    fake_gcloud = tmp_path / "gcloud"
    fake_gcloud.write_text(
        """#!/usr/bin/env bash
set -u

if test "$1 $2" = "storage cat"; then
  printf '%s\n' "$BUILD_ID"
  exit 0
fi
if test "$1 $2" = "storage rm"; then
  printf '%s\n' release >> "$FAKE_COMMAND_LOG"
  exit 0
fi
if test "$1 $2" = "builds list"; then
  printf '%s\n' "$BUILD_ID"
  exit 0
fi
if test "$1 $2 $3" = "run worker-pools describe"; then
  pool="$4"
  if test -f "$FAKE_WORKER_STATE" && test "$(< "$FAKE_WORKER_STATE")" = "$pool"; then
    printf '%s\n' "$pool-rel-$SHORT_SHA"
  else
    printf '%s\n' "$pool-previous"
  fi
  exit 0
fi
if test "$1 $2 $3" = "run worker-pools update-instance-split"; then
  pool="$4"
  split=""
  for argument in "$@"; do
    case "$argument" in
      --to-revisions=*) split="${argument#--to-revisions=}" ;;
    esac
  done
  case "$split" in
    "$pool-rel-$SHORT_SHA=100")
      printf '%s\n' "$pool" > "$FAKE_WORKER_STATE"
      printf 'candidate:%s\n' "$pool" >> "$FAKE_COMMAND_LOG"
      exit 1
      ;;
    *)
      printf 'restore:%s:%s\n' "$pool" "$split" >> "$FAKE_COMMAND_LOG"
      exit 0
      ;;
  esac
fi

printf 'unexpected:%s\n' "$*" >> "$FAKE_COMMAND_LOG"
exit 1
"""
    )
    fake_gcloud.chmod(0o755)
    environment = os.environ | {
        "BUILD_ID": "00000000-0000-0000-0000-000000000000",
        "DEPLOY_LOCK_URI": "gs://bucket/lock",
        "DEPLOY_PROJECT_ID": "project",
        "DEPLOY_TRIGGER_ID": "11111111-1111-1111-1111-111111111111",
        "FAKE_COMMAND_LOG": str(command_log),
        "FAKE_WORKER_STATE": str(worker_state),
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "REGION": "region",
        "RESOURCE_PREFIX": "shim",
        "SHORT_SHA": "abcdef0",
    }

    result = subprocess.run(
        ["bash", "-ceu", promotion],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert command_log.exists(), result.stderr
    assert command_log.read_text().splitlines() == [
        "candidate:shim-outbox-worker",
        "restore:shim-outbox-worker:shim-outbox-worker-previous=100",
        "release",
    ]


def test_production_compose_injects_only_reviewed_environment() -> None:
    production_compose = (ROOT / "docker-compose.prod.yml").read_text()

    assert "env_file:" not in production_compose
    for required in (
        'DATABASE_URL: "${DATABASE_URL:?set DATABASE_URL}"',
        'REDIS_URL: "${REDIS_URL:?set REDIS_URL}"',
        'SECRET_KEY: "${SECRET_KEY:?set SECRET_KEY}"',
        'ENCRYPTION_KEY: "${ENCRYPTION_KEY:?set ENCRYPTION_KEY}"',
        'SUPABASE_URL: "${SUPABASE_URL:?set SUPABASE_URL}"',
        'SENTRY_DSN: "${SENTRY_DSN:-}"',
        'OTEL_EXPORTER_OTLP_ENDPOINT: "${OTEL_EXPORTER_OTLP_ENDPOINT:-}"',
        'OTEL_EXPORTER_OTLP_HEADERS: "${OTEL_EXPORTER_OTLP_HEADERS:-}"',
    ):
        assert required in production_compose
    for forbidden in (
        "OPENAI_API_KEY",
        "SHIM_TEST_API_KEY",
        "SHIM_TEST_USER_PASSWORD",
    ):
        assert forbidden not in production_compose


def test_compose_test_service_disables_external_observability() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    environment = compose["services"]["test"]["environment"]

    assert environment["SENTRY_DSN"] == ""
    assert environment["OTEL_EXPORTER_OTLP_ENDPOINT"] == ""
    assert environment["OTEL_EXPORTER_OTLP_HEADERS"] == ""


def test_fresh_schema_enforces_masked_secrets_and_append_only_audit_evidence() -> None:
    migration = (
        ROOT / "ee/alembic/versions/aa8b038bc50c_architecture_baseline.py"
    ).read_text()

    assert 'sa.Column("masked_key", sa.String(length=64), nullable=False)' in migration
    assert 'name="ck_compliance_connector_masked_key"' in migration
    assert "ai_act_audit_log_reject_truncate" in migration
    assert "ai_act_audit_anchor_append_only" in migration
    assert "ai_act_audit_anchor_reject_truncate" in migration
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE" in migration
    assert "shim_audit_append" in migration
    assert "GRANT SELECT, INSERT ON TABLE" in migration


def test_trigger_functions_have_fixed_search_paths() -> None:
    migration = (
        ROOT / "ee/alembic/versions/f10e4ac92d17_harden_function_search_paths.py"
    ).read_text()

    for function_name in (
        "reject_ai_act_audit_mutation",
        "validate_compliance_finding_connector",
        "enforce_usage_ledger_immutability",
    ):
        assert function_name in migration
    assert 'sa.text("SELECT current_schema()")' in migration
    assert "SET search_path = {schema}, pg_catalog" in migration
