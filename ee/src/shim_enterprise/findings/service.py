"""The gateway and imported-log rules, their evaluation, and the OCSF form of a finding."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from functools import reduce
import operator
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import logging
import re
from typing import Any, Literal, get_args
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    Integer,
    Numeric,
    Text,
    and_,
    case,
    cast,
    distinct,
    func,
    literal_column,
    not_,
    or_,
    select,
    text,
    true,
    type_coerce,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, aggregate_order_by, array, insert
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from shim.findings import (
    Finding as FindingV1,
    FindingEvidence,
    FindingImpact,
    FindingRemediation,
    FindingSubject,
    FindingText,
    FindingWindow,
)
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.findings.models import ExternalUsageRecord, Finding
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.observability.latency import FIRST_BYTE_SQL, SWEEP_SQL
from shim_enterprise.observability.outcomes import OUTCOMES
from shim_enterprise.observability.model_inventory import (
    byok_request,
    catalog_traffic,
    registry_traffic,
    shown_model,
)
from shim_enterprise.tenants.gateway_settings import stored_settings
from shim_enterprise.tenants.models import (
    ModelDeployment,
    Organization,
    OrganizationGatewaySettings,
    ProviderSecret,
)


logger = logging.getLogger(__name__)

RETRY_STORM = "gateway.retry_storm"
REPEAT_SPEND = "gateway.repeat_spend"
UNUSED_DEPLOYMENT = "gateway.unused_deployment"
ANSWER_QUALITY = "gateway.answer_quality"
IDLE_INTERNAL_DEPLOYMENT = "gateway.idle_internal_deployment"
UNREGISTERED_MODEL = "gateway.unregistered_model"
BYOK_USAGE = "gateway.byok_usage"
TRUNCATION_RATE = "gateway.truncation_rate"
REFUSAL_RATE = "gateway.refusal_rate"
LANGUAGE_DRIFT = "gateway.language_drift"
SCHEMA_ERRORS = "gateway.schema_errors"
SOFT_REFUSALS = "gateway.soft_refusals"
OVERSIZED_PARTS = "gateway.oversized_parts"
DEAD_TOOLS = "gateway.dead_tools"
CACHE_ORDER_CHURN = "gateway.cache_order_churn"
COLD_START = "gateway.cold_start"
QUEUEING = "gateway.queueing"
LITELLM_UNREGISTERED_MODEL = "litellm.unregistered_model"
LITELLM_ERROR_RATE = "litellm.error_rate"
LITELLM_SLOW_FIRST_TOKEN = "litellm.slow_first_token"
LITELLM_RETRY_BURST = "litellm.retry_burst"
RULE_VERSION = 1
RULE_VERSIONS = {RETRY_STORM: 2, REPEAT_SPEND: 2, UNUSED_DEPLOYMENT: 2}

RETRY_BUCKET = timedelta(minutes=15)
RETRY_BUCKETS = 4
RETRY_STORM_MIN_REQUESTS = 20
REPEAT_SPEND_MIN_SHARE = Decimal("0.10")
REPEAT_SPEND_MIN_USD = Decimal("1")
ANSWER_QUALITY_WINDOW = timedelta(hours=24)
ANSWER_QUALITY_MIN_REQUESTS = 50
ANSWER_QUALITY_MIN_RATE = Decimal("0.05")
AUTO_RESOLVE_AFTER = timedelta(days=7)
# Covers the pinned SDKs' 600 s timeout plus backoff; a longer client timeout is not linked.
REPEAT_LINK_WINDOW_SECONDS = 900
# A deployment at least this old is judged on its traffic over this many days.
DEPLOYMENT_WINDOW_DAYS = 30
IDLE_DEPLOYMENT_MAX_REQUESTS = 300
UNREGISTERED_MODEL_WINDOW_DAYS = 7
UNREGISTERED_MODEL_MIN_REQUESTS = 5
BYOK_USAGE_WINDOW_DAYS = 7
BYOK_USAGE_MIN_REQUESTS = 5
OUTCOME_RATE_WINDOW_HOURS = 24
OUTCOME_RATE_MIN_SETTLED = 50
TRUNCATION_RATE_THRESHOLD = Decimal("0.05")
REFUSAL_RATE_THRESHOLD = Decimal("0.05")
# Answer quality from the response analyzers the tenant turned on (S38, S39, S40).
QUALITY_WINDOW_HOURS = 24
LANGUAGE_DRIFT_MIN_REQUESTS = 20
LANGUAGE_DRIFT_THRESHOLD = Decimal("0.10")
SCHEMA_ERRORS_MIN_CHECKED = 20
SCHEMA_ERRORS_THRESHOLD = Decimal("0.05")
SOFT_REFUSAL_MIN_ANALYSED = 50
SOFT_REFUSAL_THRESHOLD = Decimal("0.05")
SCHEMA_KINDS = ("json_schema", "json_object", "tool_args")
EVIDENCE_PROMPT_VERSIONS = 5
# Waste from the shape analyzer's records (S37) and the answers' tool calls (S32).
WASTE_WINDOW_HOURS = 24
OVERSIZED_MIN_REQUESTS = 20
OVERSIZED_TOOL_DEFINITION_CHARS = 40_000
OVERSIZED_HISTORY_MESSAGES = 100
OVERSIZED_HISTORY_CHARS = 200_000
OVERSIZED_LARGEST_PART_CHARS = 100_000
DEAD_TOOLS_WINDOW_DAYS = 30
DEAD_TOOLS_MIN_REQUESTS = 50
DEAD_TOOLS_MIN_OFFER_SHARE = Decimal("0.5")
DEAD_TOOLS_EVALUATION_HOURS = 24
CACHE_CHURN_MIN_REQUESTS = 20
CACHE_CHURN_MAX_DOMINANT_SHARE = Decimal("0.8")
CACHE_CHURN_MIN_PROMPT_TOKENS = 1_024
CACHE_CHURN_MAX_CACHE_READ_SHARE = Decimal("0.5")
EVIDENCE_DEAD_TOOLS = 20
EVIDENCE_TOOL_SETS = 3
# Latency of registry deployments, from the request timestamps.
COLD_START_WINDOW_HOURS = 24
COLD_START_LOOKBACK = timedelta(hours=24)
COLD_START_MIN_IDLE_SECONDS = 600
COLD_START_LATENCY_FACTOR = 5
COLD_START_MIN_FIRST_BYTE_MS = 10_000
COLD_START_MIN_EVENTS = 3
QUEUEING_WINDOW_HOURS = 24
QUEUEING_BASELINE_DAYS = 7
QUEUEING_MIN_BASELINE_STREAMS = 50
QUEUEING_MIN_HOUR_STREAMS = 10
QUEUEING_FACTOR = 3
QUEUEING_MIN_PEAK_CONCURRENCY = 4
QUEUEING_MIN_HOURS = 2
EVIDENCE_MARKERS = 5
# Imported LiteLLM logs: windows end at the latest imported row, not at now.
LITELLM_UNREGISTERED_WINDOW_DAYS = 7
LITELLM_UNREGISTERED_MIN_REQUESTS = 10
LITELLM_RATE_WINDOW_HOURS = 24
LITELLM_ERROR_MIN_REQUESTS = 50
LITELLM_ERROR_THRESHOLD = Decimal("0.05")
LITELLM_SLOW_MIN_ROWS = 50
LITELLM_SLOW_P95_MS = 10_000
LITELLM_BURST_WINDOW = timedelta(hours=1)
LITELLM_KEY_PREFIX = 16
# Another gateway's ids and names: only those a Finding v1 can carry are shown.
_EVIDENCE_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,200}")
_SUBJECT_ID_LENGTH = 200
# Stored values that become evidence only in these shapes: a keyed prompt digest
# and a refusal marker id of the analyzer's phrase list.
_PROMPT_HASH = re.compile(r"hmac-sha256:v1:[0-9a-f]{64}")
_MARKER_ID = re.compile(r"[a-z]{2}\.[a-z0-9_]{1,48}")
EVIDENCE_KEY_IDS = 10
EVIDENCE_MODELS = 10
EVIDENCE_MODELS_PER_KEY = 5
EVIDENCE_REQUEST_IDS = 20
# Two request ids a pair, beside the 20 request ids, within Finding v1's 50 evidence items.
EVIDENCE_PAIRS = 10
PROVIDERS = ("openai", "anthropic", "google")

STATUS_IDS = {"new": 1, "in_progress": 2, "suppressed": 3, "resolved": 4}
STATUS_RESOLVED = STATUS_IDS["resolved"]
OCSF_VERSION = "1.3.0"

SEVERITIES = ("informational", "low", "medium", "high", "critical")
# How far shim may go for a finding type, lowest first.
Mode = Literal["observe", "suggest", "auto"]
MODES: tuple[Mode, ...] = get_args(Mode)


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """A rule's constant text and ladder facts; templates take measurement names only."""

    TITLE: str
    SEVERITY_ID: int
    SUMMARY: Mapping[str, str]
    REMEDIATION_TEXT: Mapping[str, str]
    MAX_MODE: Mode
    REVERSIBLE: bool
    BLAST_RADIUS: Literal["key", "team", "deployment", "model", "tenant", "app"]
    RISK_CLASS: Literal["privacy", "cost", "reliability", "quality"]
    PLAYBOOK: str
    # The typed change a person can plan from the finding; None when the fix is
    # outside the gateway (the client, the prompt or the provider).
    ACTION_KIND: str | None = None
    # Where the evidence comes from: shim's own records or an imported log.
    SOURCE: Literal["gateway", "litellm"] = "gateway"


def _playbook(rule_id: str) -> str:
    return f"ee/docs/FINDINGS.md#{rule_id.replace('.', '')}"


RULES: dict[str, RuleSpec] = {
    RETRY_STORM: RuleSpec(
        TITLE="Retry storm from one API key",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "One API key sent {repeated_requests} repeated requests within "
            "{window_minutes} minutes; the threshold is {threshold}.",
            "tr": "Bir API anahtarı {window_minutes} dakika içinde "
            "{repeated_requests} tekrarlanan istek gönderdi; eşik {threshold}.",
        },
        REMEDIATION_TEXT={
            "en": "Find the client behind this key and make it back off: honour "
            "Retry-After, add jittered exponential backoff and cap retries. When "
            "abandoned requests co-occur, raise the client's timeout above the "
            "model's answer time instead of retrying.",
            "tr": "Bu anahtarın arkasındaki istemciyi bulun ve geri çekilmesini "
            "sağlayın: Retry-After başlığına uyun, rastgele gecikmeli üstel geri "
            "çekilme ekleyin ve yeniden denemeleri sınırlayın. Yarıda bırakılan "
            "istekler de varsa yeniden denemek yerine istemcinin zaman aşımını "
            "modelin yanıt süresinin üstüne çıkarın.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(RETRY_STORM),
    ),
    REPEAT_SPEND: RuleSpec(
        TITLE="Repeated requests are a large share of a key's spend",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "Repeated requests cost {repeated_cost_usd:.2f} USD of this API "
            "key's {known_spend_usd:.2f} USD known spend this month.",
            "tr": "Tekrarlanan istekler bu API anahtarının bu ayki "
            "{known_spend_usd:.2f} USD bilinen harcamasının "
            "{repeated_cost_usd:.2f} USD tutarındaki kısmını oluşturdu.",
        },
        REMEDIATION_TEXT={
            "en": "Stop resending identical requests from this key: retry only on "
            "retryable errors, deduplicate in the client, or cache the answer.",
            "tr": "Bu anahtardan aynı istekleri yeniden göndermeyi durdurun: yalnızca "
            "yeniden denenebilir hatalarda yeniden deneyin, istemcide "
            "tekilleştirin ya da yanıtı önbelleğe alın.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(REPEAT_SPEND),
    ),
    UNUSED_DEPLOYMENT: RuleSpec(
        TITLE="Registered deployment receives no traffic",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "This deployment has had no requests in {window_days} days.",
            "tr": "Bu dağıtım {window_days} gündür hiç istek almadı.",
        },
        REMEDIATION_TEXT={
            "en": "Disable or delete the deployment if nobody uses it, or point "
            "callers at its alias.",
            "tr": "Kimse kullanmıyorsa dağıtımı devre dışı bırakın ya da silin; ya "
            "da çağıranları takma adına yönlendirin.",
        },
        MAX_MODE="auto",
        REVERSIBLE=True,
        BLAST_RADIUS="deployment",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(UNUSED_DEPLOYMENT),
        ACTION_KIND="deployment.disable",
    ),
    ANSWER_QUALITY: RuleSpec(
        TITLE="A model often truncates, refuses or returns empty answers",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "In the last {window_hours} hours this model truncated "
            "{truncated}, left empty {empty} and refused {refused} of "
            "{settled_requests} answers.",
            "tr": "Son {window_hours} saatte bu model {settled_requests} yanıttan "
            "{truncated} tanesini kesti, {empty} tanesini boş bıraktı ve "
            "{refused} tanesini reddetti.",
        },
        REMEDIATION_TEXT={
            "en": "For truncation, raise the output token limit or shorten the "
            "expected answer; for empty or refused answers, review the prompt and "
            "the model choice.",
            "tr": "Kesilme için çıktı token sınırını yükseltin ya da beklenen yanıtı "
            "kısaltın; boş ya da reddedilen yanıtlar için istemi ve model seçimini "
            "gözden geçirin.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="model",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(ANSWER_QUALITY),
    ),
    UNREGISTERED_MODEL: RuleSpec(
        TITLE="A model outside the registry serves requests",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "{requests} requests in {window_days} days used this model through "
            "the provider's public endpoint, outside the registry.",
            "tr": "Son {window_days} günde {requests} istek bu modeli kayıt dışında, "
            "sağlayıcının genel uç noktası üzerinden kullandı.",
        },
        REMEDIATION_TEXT={
            "en": "Register the model as a deployment, or limit the keys that use it "
            "with allowed_models; an operator can make the registry mandatory with "
            "MODEL_DEPLOYMENT_REQUIRED=true.",
            "tr": "Modeli bir dağıtım olarak kaydedin ya da onu kullanan anahtarları "
            "allowed_models ile sınırlayın; bir operatör kaydı "
            "MODEL_DEPLOYMENT_REQUIRED=true ile zorunlu kılabilir.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="model",
        RISK_CLASS="privacy",
        PLAYBOOK=_playbook(UNREGISTERED_MODEL),
    ),
    BYOK_USAGE: RuleSpec(
        TITLE="An API key sends its own provider key past a stored one",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "This API key sent requests costing {cost_usd:.2f} USD with its own "
            "provider key in {window_days} days, past the provider spend limit.",
            "tr": "Bu API anahtarı {window_days} günde kendi sağlayıcı anahtarıyla "
            "{cost_usd:.2f} USD tutarında istek gönderdi; bu istekler sağlayıcı "
            "harcama sınırının dışında kaldı.",
        },
        REMEDIATION_TEXT={
            "en": "Give the app the managed key path (no x-provider-key header), or "
            "route it through a registry deployment, whose stored secret always wins.",
            "tr": "Uygulamaya yönetilen anahtar yolunu verin (x-provider-key başlığı "
            "olmadan) ya da onu, saklanan anahtarı her zaman öncelikli olan bir kayıt "
            "dağıtımı üzerinden yönlendirin.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(BYOK_USAGE),
    ),
    TRUNCATION_RATE: RuleSpec(
        TITLE="An API key's answers often stop at the output limit",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "{truncated} of {settled_requests} answers to this API key in "
            "{window_hours} hours stopped at the output limit.",
            "tr": "Son {window_hours} saatte bu API anahtarına verilen "
            "{settled_requests} yanıttan {truncated} tanesi çıktı sınırında durdu.",
        },
        REMEDIATION_TEXT={
            "en": "The answers hit the output limit: raise the max output tokens the "
            "app sends, or check the model's output limit. The request list filtered "
            "by completion_outcome=truncated and this api_key_id shows them.",
            "tr": "Yanıtlar çıktı sınırına takılıyor: uygulamanın gönderdiği en yüksek "
            "çıktı token sayısını yükseltin ya da modelin çıktı sınırını kontrol edin. "
            "completion_outcome=truncated ve bu api_key_id ile süzülen istek listesi "
            "bunları gösterir.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(TRUNCATION_RATE),
    ),
    REFUSAL_RATE: RuleSpec(
        TITLE="An API key's answers are often refused, filtered or empty",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "Of {settled_requests} answers to this API key in {window_hours} "
            "hours, {refused} were refused, {filtered} filtered and {empty} empty.",
            "tr": "Son {window_hours} saatte bu API anahtarına verilen "
            "{settled_requests} yanıttan {refused} tanesi reddedildi, {filtered} "
            "tanesi süzüldü ve {empty} tanesi boş kaldı.",
        },
        REMEDIATION_TEXT={
            "en": "Read the refused and filtered requests (the request list filtered "
            "by completion_outcome and this api_key_id): a provider content filter, a "
            "model refusal and an empty answer have different fixes.",
            "tr": "Reddedilen ve süzülen istekleri okuyun (completion_outcome ve bu "
            "api_key_id ile süzülen istek listesi): sağlayıcı içerik filtresinin, "
            "model reddinin ve boş yanıtın çözümleri farklıdır.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(REFUSAL_RATE),
    ),
    IDLE_INTERNAL_DEPLOYMENT: RuleSpec(
        TITLE="Internal deployment is almost unused",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "This internal deployment served {requests} requests in "
            "{window_days} days; the threshold is {threshold}.",
            "tr": "Bu iç dağıtım {window_days} günde {requests} istek karşıladı; "
            "eşik {threshold}.",
        },
        REMEDIATION_TEXT={
            "en": "Disable the deployment or move its few callers to another "
            "deployment; it can be enabled again in one write.",
            "tr": "Dağıtımı devre dışı bırakın ya da az sayıdaki çağıranını başka bir "
            "dağıtıma taşıyın; tek bir yazmayla yeniden etkinleştirilebilir.",
        },
        MAX_MODE="suggest",
        REVERSIBLE=True,
        BLAST_RADIUS="deployment",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(IDLE_INTERNAL_DEPLOYMENT),
        ACTION_KIND="deployment.disable",
    ),
    LANGUAGE_DRIFT: RuleSpec(
        TITLE="Turkish questions to an API key are answered in English",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "{drifts} of {analysed_requests} Turkish questions to this API key "
            "in {window_hours} hours were answered in English.",
            "tr": "Son {window_hours} saatte bu API anahtarına sorulan "
            "{analysed_requests} Türkçe sorudan {drifts} tanesi İngilizce yanıtlandı.",
        },
        REMEDIATION_TEXT={
            "en": "If the app expects English answers, suppress this finding for the "
            "key. Otherwise state the answer language in the system prompt, or compare "
            "the models the evidence lists; the prompt versions it lists show which "
            "system prompt the drifted answers had.",
            "tr": "Uygulama İngilizce yanıt bekliyorsa bu bulguyu bu anahtar için "
            "bastırın. Aksi halde sistem isteminde yanıt dilini belirtin ya da kanıtta "
            "listelenen modelleri karşılaştırın; listelenen istem sürümleri kayan "
            "yanıtların hangi sistem istemiyle geldiğini gösterir.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(LANGUAGE_DRIFT),
    ),
    SCHEMA_ERRORS: RuleSpec(
        TITLE="Answers to an API key often break the schema it asked for",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "{invalid} of {checked_requests} checked answers to this API key in "
            "{window_hours} hours did not match the schema the app asked for.",
            "tr": "Son {window_hours} saatte bu API anahtarına verilen ve denetlenen "
            "{checked_requests} yanıttan {invalid} tanesi uygulamanın istediği şemaya "
            "uymadı.",
        },
        REMEDIATION_TEXT={
            "en": "Use the provider's strict structured output where it exists, keep "
            "the schema inside the subset the gateway checks, and compare the models "
            "the evidence lists. Each request's own record holds where its answer "
            "failed.",
            "tr": "Sağlayıcının katı yapılandırılmış çıktısını destekleniyorsa "
            "kullanın, şemayı gateway'in denetlediği alt küme içinde tutun ve kanıtta "
            "listelenen modelleri karşılaştırın. Yanıtın nerede uymadığı her isteğin "
            "kendi kaydında yazar.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(SCHEMA_ERRORS),
    ),
    SOFT_REFUSALS: RuleSpec(
        TITLE="Answers to an API key often refuse in words",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "{soft_refusals} of {analysed_requests} complete answers to this API "
            "key in {window_hours} hours refused in words.",
            "tr": "Son {window_hours} saatte bu API anahtarına verilen "
            "{analysed_requests} tam yanıttan {soft_refusals} tanesi sözle reddetti.",
        },
        REMEDIATION_TEXT={
            "en": "Read the requests: a polite refusal often means the system prompt "
            "forbids the topic, or the model's own policy differs from the app's. "
            "Refusals the provider marks itself are gateway.refusal_rate.",
            "tr": "İstekleri okuyun: kibar bir ret çoğu zaman sistem isteminin konuyu "
            "yasakladığını ya da modelin kendi politikasının uygulamanınkinden farklı "
            "olduğunu gösterir. Sağlayıcının kendisinin işaretlediği retler "
            "gateway.refusal_rate'tedir.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(SOFT_REFUSALS),
    ),
    OVERSIZED_PARTS: RuleSpec(
        TITLE="Requests from an API key carry oversized parts",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "Over {window_hours} hours the median request from this API key "
            "crossed the size limit in {crossed_kinds} part kinds, over "
            "{analysed_requests} requests.",
            "tr": "Son {window_hours} saatte bu API anahtarının {analysed_requests} "
            "isteğinde ortanca istek {crossed_kinds} parça türünde boyut sınırını aştı.",
        },
        REMEDIATION_TEXT={
            "en": "Send only the tools the task needs, or load them when needed; trim "
            "or summarise the history in the app; send the relevant part of a "
            "document instead of all of it.",
            "tr": "Yalnızca görevin gerektirdiği araçları gönderin ya da gerektiğinde "
            "yükleyin; geçmişi uygulamada kısaltın ya da özetleyin; belgenin tamamı "
            "yerine ilgili bölümünü gönderin.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(OVERSIZED_PARTS),
    ),
    DEAD_TOOLS: RuleSpec(
        TITLE="An API key offers tools its answers never call",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "This API key offered {dead_tools} tools in at least half of its "
            "{offering_requests} requests with tools over {window_days} days, and no "
            "answer called them.",
            "tr": "Bu API anahtarı son {window_days} günde araç sunduğu "
            "{offering_requests} isteğin en az yarısında {dead_tools} aracı sundu ve "
            "hiçbir yanıt onları çağırmadı.",
        },
        REMEDIATION_TEXT={
            "en": "Remove the tools the app never calls, or load them only when "
            "needed. If the app's tool calls go through a path shim does not see, "
            "suppress the finding.",
            "tr": "Uygulamanın hiç çağırmadığı araçları kaldırın ya da yalnızca "
            "gerektiğinde yükleyin. Uygulamanın araç çağrıları shim'in görmediği bir "
            "yoldan geçiyorsa bulguyu bastırın.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(DEAD_TOOLS),
    ),
    CACHE_ORDER_CHURN: RuleSpec(
        TITLE="An API key sends its tools in changing order and misses the cache",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "Over {window_hours} hours this API key sent the same tool set in "
            "{orders} orders across {churned_requests} requests, and the provider's "
            "prompt cache rarely applied.",
            "tr": "Son {window_hours} saatte bu API anahtarı aynı araç kümesini "
            "{churned_requests} istekte {orders} farklı sırayla gönderdi ve "
            "sağlayıcının istem önbelleği nadiren devreye girdi.",
        },
        REMEDIATION_TEXT={
            "en": "Send the tools in a fixed order, for example sorted by name, and "
            "keep the system prompt free of per-request values; the provider's prompt "
            "cache then applies to the shared prefix.",
            "tr": "Araçları sabit bir sırayla, örneğin ada göre sıralı gönderin ve "
            "sistem istemine isteğe göre değişen değerler koymayın; sağlayıcının "
            "istem önbelleği o zaman ortak önek için devreye girer.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(CACHE_ORDER_CHURN),
    ),
    COLD_START: RuleSpec(
        TITLE="A deployment answers slowly after it was idle",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "{cold_starts} requests to this deployment in {window_hours} hours "
            "waited for a cold start after an idle gap; {timeouts} of them timed out.",
            "tr": "Son {window_hours} saatte bu dağıtıma gelen {cold_starts} istek "
            "boşta kalmanın ardından soğuk başlatmayı bekledi; {timeouts} tanesi zaman "
            "aşımına uğradı.",
        },
        REMEDIATION_TEXT={
            "en": "Keep the model loaded between requests with the model server's "
            "keep-alive or idle-unload setting, or raise the deployment's timeout when "
            "cold starts end in timeouts.",
            "tr": "Model sunucusunun keep-alive ya da boşta bellekten çıkarma ayarıyla "
            "modeli istekler arasında yüklü tutun; soğuk başlatmalar zaman aşımıyla "
            "bitiyorsa dağıtımın zaman aşımını yükseltin.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="deployment",
        RISK_CLASS="reliability",
        PLAYBOOK=_playbook(COLD_START),
    ),
    QUEUEING: RuleSpec(
        TITLE="Streams to a deployment wait in a queue at busy hours",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "In {congested_hours} hours of the last {window_hours}, streams to "
            "this deployment were slow to start, up to {worst_ttft_p95_ms} ms for a "
            "first byte against a usual {baseline_ttft_ms} ms, with up to "
            "{peak_concurrency} in flight at once.",
            "tr": "Son {window_hours} saatin {congested_hours} saatinde bu dağıtıma "
            "gelen akışlar ilk bayt için {worst_ttft_p95_ms} ms'ye kadar bekledi; "
            "olağan süre {baseline_ttft_ms} ms, aynı anda en çok {peak_concurrency} "
            "istek vardı.",
        },
        REMEDIATION_TEXT={
            "en": "Give the deployment more capacity, set a concurrency budget for "
            "the target, or send long requests to their own lane. The latency read "
            "grouped by deployment shows the hours.",
            "tr": "Dağıtıma daha fazla kapasite verin, hedef için bir eşzamanlılık "
            "bütçesi tanımlayın ya da uzun istekleri kendi şeridine gönderin. "
            "Dağıtıma göre gruplanan gecikme okuması saatleri gösterir.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="deployment",
        RISK_CLASS="reliability",
        PLAYBOOK=_playbook(QUEUEING),
    ),
    LITELLM_UNREGISTERED_MODEL: RuleSpec(
        TITLE="LiteLLM serves a model outside the registry",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "{requests} LiteLLM requests in {window_days} days used this model, "
            "which matches no registry deployment.",
            "tr": "Son {window_days} günde {requests} LiteLLM isteği bu modeli "
            "kullandı; model hiçbir kayıtlı dağıtımla eşleşmiyor.",
        },
        REMEDIATION_TEXT={
            "en": "Register the model as a deployment if it is meant to be used, or "
            "remove it from the LiteLLM configuration. The finding reads LiteLLM's "
            "own log, not shim's records.",
            "tr": "Model kullanılacaksa onu bir dağıtım olarak kaydedin, değilse "
            "LiteLLM yapılandırmasından çıkarın. Bulgu shim kayıtlarını değil, "
            "LiteLLM'in kendi kaydını okur.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="model",
        RISK_CLASS="privacy",
        PLAYBOOK=_playbook(LITELLM_UNREGISTERED_MODEL),
        SOURCE="litellm",
    ),
    LITELLM_ERROR_RATE: RuleSpec(
        TITLE="A model often fails behind LiteLLM",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "{failed_requests} of {requests} LiteLLM requests for this model "
            "failed in {window_hours} hours of the imported log.",
            "tr": "İçe aktarılan kaydın {window_hours} saatinde bu model için "
            "{requests} LiteLLM isteğinden {failed_requests} tanesi başarısız oldu.",
        },
        REMEDIATION_TEXT={
            "en": "Read the failed requests in LiteLLM by the request ids in the "
            "evidence: a wrong key, a retired model or a provider limit fails every "
            "call the same way.",
            "tr": "Başarısız istekleri kanıttaki istek kimlikleriyle LiteLLM'de "
            "okuyun: yanlış bir anahtar, emekliye ayrılmış bir model ya da bir "
            "sağlayıcı sınırı her çağrıyı aynı şekilde başarısız kılar.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="model",
        RISK_CLASS="reliability",
        PLAYBOOK=_playbook(LITELLM_ERROR_RATE),
        SOURCE="litellm",
    ),
    LITELLM_SLOW_FIRST_TOKEN: RuleSpec(
        TITLE="A model is slow to its first token behind LiteLLM",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "In {window_hours} hours, {requests} LiteLLM streams for this "
            "model had a ninety-fifth percentile time to first token of "
            "{ttft_ms_p95} ms.",
            "tr": "Son {window_hours} saatte bu model için {requests} LiteLLM "
            "isteğinde ilk tokene kadar geçen sürenin yüzde doksan beşlik dilimi "
            "{ttft_ms_p95} ms oldu.",
        },
        REMEDIATION_TEXT={
            "en": "Check the deployment's capacity and queue at the busy hours, or "
            "move latency-sensitive traffic to a faster model. LiteLLM records the "
            "first token only for streams.",
            "tr": "Yoğun saatlerde dağıtımın kapasitesine ve kuyruğuna bakın ya da "
            "gecikmeye duyarlı trafiği daha hızlı bir modele taşıyın. LiteLLM ilk "
            "tokeni yalnızca akışlarda kaydeder.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="model",
        RISK_CLASS="reliability",
        PLAYBOOK=_playbook(LITELLM_SLOW_FIRST_TOKEN),
        SOURCE="litellm",
    ),
    LITELLM_RETRY_BURST: RuleSpec(
        TITLE="A LiteLLM key repeats the same-sized request",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "One LiteLLM key sent {repeated_requests} requests of the same model "
            "and prompt size within {window_minutes} minutes; the threshold is "
            "{threshold}. LiteLLM keeps no content digest, so equal token counts "
            "stand in for equal requests.",
            "tr": "Bir LiteLLM anahtarı {window_minutes} dakika içinde aynı model ve "
            "aynı istem boyutunda {repeated_requests} istek gönderdi; eşik "
            "{threshold}. LiteLLM içerik özeti tutmadığından eşit token sayıları "
            "aynı isteğin yerine geçer.",
        },
        REMEDIATION_TEXT={
            "en": "Find the client behind this LiteLLM key and make it back off: "
            "honour Retry-After, add jittered exponential backoff and cap retries. "
            "Behind shim the same pattern is measured on content as "
            "gateway.retry_storm.",
            "tr": "Bu LiteLLM anahtarının arkasındaki istemciyi bulun ve geri "
            "çekilmesini sağlayın: Retry-After başlığına uyun, rastgele gecikmeli "
            "üstel geri çekilme ekleyin ve yeniden denemeleri sınırlayın. shim "
            "arkasında aynı örüntü içerik üzerinden gateway.retry_storm olarak "
            "ölçülür.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(LITELLM_RETRY_BURST),
        SOURCE="litellm",
    ),
}


def effective_mode(rule_id: str, modes: Mapping[str, Mode]) -> Mode:
    mode = min(modes.get(rule_id, "observe"), RULES[rule_id].MAX_MODE, key=MODES.index)
    # No executor applies anything yet (E56): auto works as suggest.
    return "suggest" if mode == "auto" else mode


def ladder_remediation(
    rule_id: str, subject: Mapping[str, Any], modes: Mapping[str, Mode]
) -> dict[str, Any]:
    """The ladder fields a finding stores: built from its subject, never from content."""
    spec, mode = RULES[rule_id], effective_mode(rule_id, modes)
    action = None
    if mode != "observe" and spec.ACTION_KIND == "deployment.disable":
        action = {
            "kind": spec.ACTION_KIND,
            "params": {"deployment_id": str(subject["deployment_id"])},
        }
    return {
        "mode": mode,
        "max_mode": spec.MAX_MODE,
        "action": action,
        "reversible": spec.REVERSIBLE,
        "blast_radius": spec.BLAST_RADIUS,
        "proof_after": None,
    }


async def apply_modes(
    session: AsyncSession, tenant_id: UUID, modes: Mapping[str, Mode]
) -> None:
    """Bring every open finding to the tenant's modes, fired in this pass or not."""
    for row in await session.scalars(
        select(Finding).where(
            Finding.organization_id == tenant_id,
            Finding.status_id != STATUS_RESOLVED,
            Finding.rule_id.in_(list(RULES)),
        )
    ):
        ladder = ladder_remediation(row.rule_id, row.subject, modes)
        if any(row.remediation.get(key) != value for key, value in ladder.items()):
            row.remediation = {**row.remediation, **ladder}


async def finding_modes(session: AsyncSession, tenant_id: UUID) -> dict[str, Mode]:
    stored = await session.scalar(
        select(OrganizationGatewaySettings.settings).where(
            OrganizationGatewaySettings.organization_id == tenant_id
        )
    )
    return {} if stored is None else stored_settings(stored).finding_modes


# A retry storm's fix follows the class most of its repeats belong to.
STORM_FIXES: dict[str, Mapping[str, str]] = {
    "after_timeout": {
        "en": "The client's timeout is shorter than the answers take: raise the "
        "timeout or ask for fewer output tokens instead of sending the request again.",
        "tr": "İstemcinin zaman aşımı yanıtların süresinden kısa: isteği yeniden "
        "göndermek yerine zaman aşımını yükseltin ya da daha az çıktı tokenı isteyin.",
    },
    "after_error": {
        "en": "The SDK retries after errors: honour Retry-After, lower max_retries "
        "and add jittered backoff.",
        "tr": "SDK hatalardan sonra yeniden deniyor: Retry-After başlığına uyun, "
        "max_retries değerini düşürün ve rastgele gecikmeli geri çekilme ekleyin.",
    },
    "after_success": {
        "en": "The app sends the same request again after a successful answer: "
        "deduplicate it in the app.",
        "tr": "Uygulama başarılı bir yanıttan sonra aynı isteği yeniden gönderiyor: "
        "uygulamada tekilleştirin.",
    },
}
REPEAT_CLASSES = ("after_timeout", "after_error", "after_success", "pending")
_TIMED_OUT = ("client_disconnected", "timeout")
_FAILED = ("provider_error", "failed", "rejected", "internal_error", "cancelled")


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def measurements(evidence: Mapping[str, Any]) -> dict[str, int | float]:
    """The numbers of a row's evidence; request ids and other strings stay out.

    Counts keyed by a stored word take a name from a fixed vocabulary: repeat
    classes become `repeats_<class>`, providers `requests_<provider>` (or
    `requests_other`), and linked pairs `pairs` shown and `pairs_omitted`.
    """

    values: dict[str, int | float] = {}
    for name, value in evidence.items():
        if name == "classes" and isinstance(value, Mapping):
            for kind in REPEAT_CLASSES:
                if _count(value.get(kind)):
                    values[f"repeats_{kind}"] = value[kind]
        elif name == "requests" and isinstance(value, Mapping):
            for provider, count in value.items():
                if _count(count):
                    key = f"requests_{provider if provider in PROVIDERS else 'other'}"
                    values[key] = values.get(key, 0) + count
        elif name == "pairs" and isinstance(value, list):
            values["pairs"] = min(len(value), EVIDENCE_PAIRS)
        elif isinstance(value, bool):
            continue
        elif isinstance(value, int):
            values[name] = value
        elif isinstance(value, (float, str)):
            try:
                number = Decimal(str(value))
            except InvalidOperation:
                continue
            if number.is_finite():
                values[name] = float(number)
    if "pairs" in values:
        linked = sum(values.get(f"repeats_{kind}", 0) for kind in REPEAT_CLASSES)
        values["pairs_omitted"] = max(0, linked - values["pairs"])
    return values


def render(template: str, values: Mapping[str, int | float]) -> str:
    return template.format(**values)


def remediation_text(rule_id: str, evidence: Mapping[str, Any]) -> Mapping[str, str]:
    """The rule's fix; a retry storm's follows the class most of its repeats belong to."""

    classes = evidence.get("classes") if rule_id == RETRY_STORM else None
    if isinstance(classes, Mapping):
        cause = max(STORM_FIXES, key=lambda name: classes.get(name) or 0)
        if classes.get(cause):
            return STORM_FIXES[cause]
    return RULES[rule_id].REMEDIATION_TEXT


_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    subject_key: str
    subject: dict[str, Any]
    evidence: dict[str, Any]
    impact: dict[str, Any] | None = None


def _request_ids(
    condition: Any,
    request_id: Any = RequestLifecycle.request_id,
    started_at: Any = RequestLifecycle.started_at,
) -> Any:
    ordered = func.array_agg(aggregate_order_by(request_id, started_at)).filter(
        condition
    )
    return type_coerce(ordered, ARRAY(Text))[1:EVIDENCE_REQUEST_IDS]


def _priced_settlement(request_id: Any, tenant_id: UUID) -> Any:
    # One settlement per request at most, so this join never repeats a row.
    return (
        (UsageLedger.organization_id == tenant_id)
        & (UsageLedger.request_id == request_id)
        & (UsageLedger.event_type == "spend_settlement")
        & UsageLedger.event_metadata["pricing"]["pricing_resolution"]
        .as_string()
        .is_distinct_from("unknown")
    )


def _repeats(tenant_id: UUID, start: datetime, end: datetime) -> Any:
    """Each request of the window with its settlement and the request before it."""
    metadata = RequestLifecycle.lifecycle_metadata
    # Narrow columns only: the window sorts these rows, and the metadata they come
    # from is many times wider. MATERIALIZED stops Postgres folding the projection
    # back into the scan and carrying the metadata through the join and the sort.
    requests = (
        select(
            RequestLifecycle.id,
            RequestLifecycle.request_id,
            RequestLifecycle.api_key_id,
            RequestLifecycle.started_at,
            RequestLifecycle.status,
            # Null without prompt material, before digests, and (JSON null) with
            # personal data.
            metadata["repeat_digest"].as_string().label("digest"),
            metadata["repeat_chain_length"].as_integer().label("chain"),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            # The link window before start lets a repeat at the window's edge find
            # its predecessor.
            RequestLifecycle.started_at
            >= start - timedelta(seconds=REPEAT_LINK_WINDOW_SECONDS),
            RequestLifecycle.started_at < end,
            RequestLifecycle.api_key_id.is_not(None),
        )
        .cte("requests")
        .prefix_with("MATERIALIZED")
    )
    # One settlement per request at most, so this join never repeats a row.
    settlement = aliased(UsageLedger)
    billed = settlement.id.is_not(None)

    def previous(column: Any) -> Any:
        return func.lag(column).over(
            partition_by=(requests.c.api_key_id, requests.c.digest),
            order_by=(requests.c.started_at, requests.c.id),
        )

    return (
        select(
            requests.c.request_id,
            requests.c.api_key_id,
            requests.c.started_at,
            requests.c.status,
            requests.c.chain,
            case(
                (
                    settlement.event_metadata["pricing"]["pricing_resolution"]
                    .as_string()
                    .is_distinct_from("unknown"),
                    settlement.cost_usd,
                )
            ).label("cost"),
            requests.c.digest.is_not(None).label("digested"),
            (requests.c.chain >= 2).label("chained"),
            previous(requests.c.chain).label("previous_chain"),
            previous(billed).label("previous_billed"),
            previous(requests.c.request_id).label("previous_id"),
            previous(requests.c.started_at).label("previous_at"),
            previous(requests.c.status).label("previous_status"),
        )
        .select_from(requests)
        .outerjoin(
            settlement,
            (settlement.organization_id == tenant_id)
            & (settlement.request_id == requests.c.request_id)
            & (settlement.event_type == "spend_settlement"),
        )
        .subquery("repeats")
    )


def _repeat_terms(rows: Any) -> SimpleNamespace:
    link = timedelta(seconds=REPEAT_LINK_WINDOW_SECONDS)
    linked = and_(
        rows.c.digested,
        rows.c.previous_id.is_not(None),
        rows.c.started_at - rows.c.previous_at <= link,
    )
    kind = case(
        (rows.c.previous_status.in_(_TIMED_OUT), "after_timeout"),
        (rows.c.previous_status.in_(_FAILED), "after_error"),
        (rows.c.previous_status == "completed", "after_success"),
        else_="pending",
    )
    gap = func.extract("epoch", rows.c.started_at - rows.c.previous_at)
    pair = func.jsonb_build_object(
        "repeat",
        rows.c.request_id,
        "previous",
        rows.c.previous_id,
        "class",
        kind,
        "gap_seconds",
        func.round(gap),
    )
    unlinked = and_(not_(rows.c.digested), rows.c.chained)
    return SimpleNamespace(
        rows=rows,
        linked=linked,
        repeat=or_(linked, unlinked),
        # A chain without a digest has no link, but when the key's previous such
        # request carries one repeat less and was refunded, this is its retry.
        legacy=and_(
            unlinked,
            not_(
                and_(
                    rows.c.previous_chain.is_not_distinct_from(rows.c.chain - 1),
                    rows.c.started_at - rows.c.previous_at <= link,
                    not_(rows.c.previous_billed),
                )
            ),
        ),
        kind=kind,
        gap=gap,
        billed=func.coalesce(rows.c.previous_billed, False),
        pairs=func.array_to_json(
            type_coerce(
                func.array_agg(aggregate_order_by(pair, rows.c.started_at)).filter(
                    linked
                ),
                ARRAY(JSONB),
            )[1:EVIDENCE_REQUEST_IDS],
            type_=JSONB,
        ),
        classes=[
            func.count().filter(linked, kind == name).label(name)
            for name in REPEAT_CLASSES
        ],
    )


async def linked_repeats(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> list[Any]:
    """Every repeat started in [start, end) linked to the request it repeats."""
    terms = _repeat_terms(_repeats(tenant_id, start, end))
    rows = terms.rows
    return list(
        await session.execute(
            select(
                rows.c.request_id,
                rows.c.previous_id,
                rows.c.api_key_id,
                terms.gap.label("gap_seconds"),
                rows.c.previous_status,
                terms.kind.label("repeat_class"),
                terms.billed.label("previous_billed"),
                rows.c.cost.label("cost_usd"),
            )
            .where(rows.c.started_at >= start, terms.linked)
            .order_by(rows.c.started_at, rows.c.request_id)
        )
    )


def _classes(row: Any) -> dict[str, int]:
    return {name: getattr(row, name) for name in REPEAT_CLASSES}


async def _retry_storms(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    current = _EPOCH + (now - _EPOCH) // RETRY_BUCKET * RETRY_BUCKET
    start = current - RETRY_BUCKET * (RETRY_BUCKETS - 1)
    terms = _repeat_terms(_repeats(tenant_id, start, now))
    rows = terms.rows
    bucket = func.date_bin(RETRY_BUCKET, rows.c.started_at, _EPOCH)
    count = func.count().filter(terms.repeat)
    result = await session.execute(
        select(
            rows.c.api_key_id,
            bucket.label("bucket"),
            count.label("repeated"),
            func.count().filter(rows.c.status.in_(_TIMED_OUT)).label("abandoned"),
            func.coalesce(
                func.sum(rows.c.cost).filter(terms.repeat), Decimal("0")
            ).label("cost"),
            _request_ids(terms.repeat, rows.c.request_id, rows.c.started_at).label(
                "request_ids"
            ),
            terms.pairs.label("pairs"),
            *terms.classes,
        )
        .where(rows.c.started_at >= start)
        .group_by(rows.c.api_key_id, bucket)
        .having(count >= RETRY_STORM_MIN_REQUESTS)
        .order_by(rows.c.api_key_id, count.desc(), bucket.desc())
    )
    worst: dict[UUID, Any] = {}
    for row in result:
        worst.setdefault(row.api_key_id, row)
    detections = []
    for key_id, row in worst.items():
        classes = _classes(row)
        detections.append(
            Detection(
                rule_id=RETRY_STORM,
                subject_key=f"api_key:{key_id}",
                subject={"api_key_id": str(key_id)},
                evidence={
                    "window_start": row.bucket.isoformat(),
                    "window_minutes": 15,
                    "repeated_requests": row.repeated,
                    "threshold": RETRY_STORM_MIN_REQUESTS,
                    "abandoned_requests": row.abandoned,
                    "request_ids": list(row.request_ids or []),
                    "classes": classes,
                    "pairs": row.pairs or [],
                },
                impact={"cost_usd": str(row.cost), "requests": row.repeated},
            )
        )
    return detections


async def _repeat_spend(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    month_start = now.astimezone(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    terms = _repeat_terms(_repeats(tenant_id, month_start, now))
    rows = terms.rows
    # A repeat of a refunded request did not double the bill.
    counted = or_(and_(terms.linked, terms.billed), terms.legacy)
    known = func.coalesce(func.sum(rows.c.cost), Decimal("0"))
    repeated_cost = func.coalesce(func.sum(rows.c.cost).filter(counted), Decimal("0"))
    # The window sort of a busy month needs more than the 4MB default to stay in memory.
    await session.execute(text("SET LOCAL work_mem = '32MB'"))
    result = await session.execute(
        select(
            rows.c.api_key_id,
            known.label("known"),
            repeated_cost.label("repeated_cost"),
            func.count().filter(counted).label("repeated"),
            func.count().filter(terms.linked, terms.billed).label("billed"),
            func.count()
            .filter(terms.linked, not_(terms.billed), terms.kind != "pending")
            .label("unbilled"),
            _request_ids(counted, rows.c.request_id, rows.c.started_at).label(
                "request_ids"
            ),
            terms.pairs.label("pairs"),
            *terms.classes,
        )
        .where(rows.c.started_at >= month_start)
        .group_by(rows.c.api_key_id)
        .having(
            repeated_cost >= REPEAT_SPEND_MIN_USD,
            repeated_cost >= known * REPEAT_SPEND_MIN_SHARE,
        )
        .order_by(rows.c.api_key_id)
    )
    return [
        Detection(
            rule_id=REPEAT_SPEND,
            subject_key=f"api_key:{row.api_key_id}",
            subject={"api_key_id": str(row.api_key_id)},
            evidence={
                "period_start": month_start.isoformat(),
                "repeated_cost_usd": str(row.repeated_cost),
                "known_spend_usd": str(row.known),
                "share": str(round(row.repeated_cost / row.known, 4)),
                "repeated_requests": row.repeated,
                "request_ids": list(row.request_ids or []),
                "classes": _classes(row),
                "billed_repeats": row.billed,
                "unbilled_repeats": row.unbilled,
                "pairs": row.pairs or [],
            },
            impact={"cost_usd": str(row.repeated_cost), "requests": row.repeated},
        )
        for row in result
    ]


async def _deployments(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    """Unused and idle internal deployments, from one read of their traffic."""
    window = timedelta(days=DEPLOYMENT_WINDOW_DAYS)
    deployments = (
        await session.execute(
            select(
                ModelDeployment.id,
                ModelDeployment.alias,
                ModelDeployment.deployment_kind,
                ModelDeployment.created_at,
            )
            .where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.enabled.is_(True),
                ModelDeployment.created_at <= now - window,
            )
            .order_by(ModelDeployment.alias)
        )
    ).all()
    if not deployments:
        return []
    joined, target = registry_traffic(tenant_id)
    traffic = {
        row.deployment_id: row
        for row in await session.execute(
            select(
                target.label("deployment_id"),
                func.count().label("requests"),
                func.count(
                    func.distinct(
                        func.date(func.timezone("UTC", RequestLifecycle.started_at))
                    )
                ).label("active_days"),
                func.max(RequestLifecycle.started_at).label("last_request_at"),
                func.count(func.distinct(RequestLifecycle.api_key_id)).label(
                    "api_keys"
                ),
                _request_ids(True).label("request_ids"),
            )
            .select_from(joined)
            .where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= now - window,
                RequestLifecycle.started_at <= now,
                target.in_([str(row.id) for row in deployments]),
            )
            .group_by(target)
        )
    }
    detections = []
    for row in deployments:
        used = traffic.get(str(row.id))
        if used is None:
            detections.append(
                Detection(
                    rule_id=UNUSED_DEPLOYMENT,
                    subject_key=f"deployment:{row.alias}",
                    subject={"deployment_id": str(row.id), "alias": row.alias},
                    evidence={
                        "created_at": row.created_at.isoformat(),
                        "window_days": DEPLOYMENT_WINDOW_DAYS,
                        "requests": 0,
                    },
                )
            )
        # External deployments hold no hardware of the tenant.
        elif (
            row.deployment_kind == "internal"
            and used.requests < IDLE_DEPLOYMENT_MAX_REQUESTS
        ):
            detections.append(
                Detection(
                    rule_id=IDLE_INTERNAL_DEPLOYMENT,
                    subject_key=str(row.id),
                    subject={"deployment_id": str(row.id), "alias": row.alias},
                    evidence={
                        "window_days": DEPLOYMENT_WINDOW_DAYS,
                        "requests": used.requests,
                        "threshold": IDLE_DEPLOYMENT_MAX_REQUESTS,
                        "active_days": used.active_days,
                        "last_request_at": used.last_request_at.isoformat(),
                        "api_keys": used.api_keys,
                        "request_ids": list(used.request_ids or []),
                        "hardware_cost": "not recorded",
                    },
                    impact={"cost_usd": None, "requests": used.requests},
                )
            )
    return detections


async def _unregistered_models(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    # A tenant without a registry routes by catalog on purpose.
    if not await session.scalar(
        select(ModelDeployment.id)
        .where(
            ModelDeployment.organization_id == tenant_id,
            ModelDeployment.enabled.is_(True),
        )
        .limit(1)
    ):
        return []
    window = (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at
        >= now - timedelta(days=UNREGISTERED_MODEL_WINDOW_DAYS),
        RequestLifecycle.started_at <= now,
    )
    catalog, model = catalog_traffic(*window)
    count = func.count()
    rows = await session.execute(
        select(
            RequestLifecycle.provider,
            model.label("model"),
            count.label("requests"),
            func.count(func.distinct(RequestLifecycle.api_key_id)).label("keys"),
            type_coerce(
                func.array_agg(func.distinct(cast(RequestLifecycle.api_key_id, Text))),
                ARRAY(Text),
            )[1:EVIDENCE_KEY_IDS].label("key_ids"),
            func.count(
                func.distinct(
                    RequestLifecycle.lifecycle_metadata["team_id"].as_string()
                )
            ).label("teams"),
            func.min(RequestLifecycle.started_at).label("first_seen"),
            func.max(RequestLifecycle.started_at).label("last_seen"),
            _request_ids(True).label("request_ids"),
            func.count().filter(byok_request()).label("byok"),
            func.coalesce(func.sum(UsageLedger.cost_usd), Decimal("0")).label("cost"),
        )
        .select_from(
            catalog.outerjoin(
                UsageLedger, _priced_settlement(RequestLifecycle.request_id, tenant_id)
            )
        )
        .where(*window)
        .group_by(RequestLifecycle.provider, model)
        .having(count >= UNREGISTERED_MODEL_MIN_REQUESTS)
        .order_by(RequestLifecycle.provider, model)
    )
    return [
        Detection(
            rule_id=UNREGISTERED_MODEL,
            subject_key=f"{row.provider}:{row.model}",
            subject={"provider": row.provider, "model": row.model},
            evidence={
                "window_days": UNREGISTERED_MODEL_WINDOW_DAYS,
                "requests": row.requests,
                "threshold": UNREGISTERED_MODEL_MIN_REQUESTS,
                "api_keys": row.keys,
                "api_key_ids": sorted(row.key_ids or []),
                "teams": row.teams,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
                "request_ids": list(row.request_ids or []),
                "byok_requests": row.byok,
            },
            impact={"cost_usd": str(row.cost), "requests": row.requests},
        )
        for row in rows
    ]


async def _byok_usage(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    # A tenant that never stored a provider key uses its own keys as its only mode.
    managed = select(ProviderSecret.provider).where(
        ProviderSecret.organization_id == tenant_id
    )
    window = (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= now - timedelta(days=BYOK_USAGE_WINDOW_DAYS),
        RequestLifecycle.started_at <= now,
    )
    # A caller's own provider key is honoured on catalog routes only.
    catalog, model = catalog_traffic(*window)
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            RequestLifecycle.provider,
            func.count().label("requests"),
            type_coerce(func.array_agg(func.distinct(model)), ARRAY(Text))[
                1:EVIDENCE_MODELS
            ].label("models"),
            _request_ids(True).label("request_ids"),
            func.coalesce(func.sum(UsageLedger.cost_usd), Decimal("0")).label("cost"),
        )
        .select_from(
            catalog.outerjoin(
                UsageLedger, _priced_settlement(RequestLifecycle.request_id, tenant_id)
            )
        )
        .where(
            *window,
            RequestLifecycle.api_key_id.is_not(None),
            RequestLifecycle.provider.in_(managed),
            byok_request(),
        )
        .group_by(RequestLifecycle.api_key_id, RequestLifecycle.provider)
        .order_by(RequestLifecycle.api_key_id, RequestLifecycle.provider)
    )
    by_key: dict[UUID, list[Any]] = {}
    for row in rows:
        by_key.setdefault(row.api_key_id, []).append(row)
    detections = []
    for key_id, providers in by_key.items():
        requests = sum(row.requests for row in providers)
        if requests < BYOK_USAGE_MIN_REQUESTS:
            continue
        cost = sum((row.cost for row in providers), Decimal("0"))
        detections.append(
            Detection(
                rule_id=BYOK_USAGE,
                subject_key=f"api_key:{key_id}",
                subject={"api_key_id": str(key_id)},
                evidence={
                    "window_days": BYOK_USAGE_WINDOW_DAYS,
                    "requests": {row.provider: row.requests for row in providers},
                    "threshold": BYOK_USAGE_MIN_REQUESTS,
                    "models": sorted(
                        {model for row in providers for model in row.models or []}
                    )[:EVIDENCE_MODELS],
                    "request_ids": [
                        request
                        for row in providers
                        for request in row.request_ids or []
                    ][:EVIDENCE_REQUEST_IDS],
                    "cost_usd": str(cost),
                    "note": "These requests skipped the provider spend limit and the "
                    "tenant's stored provider key.",
                },
                impact={"cost_usd": str(cost), "requests": requests},
            )
        )
    return detections


def _outcome_counts() -> tuple[Any, Any, tuple[Any, ...]]:
    """The answer's outcome, the settled count, and the settled and per-outcome columns."""
    outcome = RequestLifecycle.lifecycle_metadata["completion_outcome"].as_string()
    settled = func.count().filter(outcome.is_not(None))
    return (
        outcome,
        settled,
        (
            settled.label("settled"),
            *(func.count().filter(outcome == name).label(name) for name in OUTCOMES),
        ),
    )


async def _answer_quality(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    model = shown_model(
        func.coalesce(RequestLifecycle.provider_model, RequestLifecycle.requested_model)
    )
    outcome, settled, counts = _outcome_counts()
    rows = await session.execute(
        select(
            model.label("model"),
            *counts,
            _request_ids(outcome.in_(("truncated", "empty", "refused"))).label(
                "request_ids"
            ),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= now - ANSWER_QUALITY_WINDOW,
            RequestLifecycle.started_at <= now,
        )
        .group_by(model)
        .having(settled >= ANSWER_QUALITY_MIN_REQUESTS)
        .order_by(model)
    )
    detections = []
    for row in rows:
        truncated_rate = Decimal(row.truncated) / row.settled
        unanswered_rate = Decimal(row.empty + row.refused) / row.settled
        if max(truncated_rate, unanswered_rate) < ANSWER_QUALITY_MIN_RATE:
            continue
        detections.append(
            Detection(
                rule_id=ANSWER_QUALITY,
                subject_key=f"model:{row.model}",
                subject={"model": row.model},
                evidence={
                    "window_hours": 24,
                    "settled_requests": row.settled,
                    "truncated": row.truncated,
                    "empty": row.empty,
                    "refused": row.refused,
                    "truncated_rate": str(round(truncated_rate, 4)),
                    "empty_or_refused_rate": str(round(unanswered_rate, 4)),
                    "threshold_rate": str(ANSWER_QUALITY_MIN_RATE),
                    "request_ids": list(row.request_ids or []),
                },
            )
        )
    return detections


async def _outcome_rates(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    outcome, settled, counts = _outcome_counts()
    unanswered = outcome.in_(("refused", "filtered", "empty"))
    window = (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= now - timedelta(hours=OUTCOME_RATE_WINDOW_HOURS),
        RequestLifecycle.started_at <= now,
        RequestLifecycle.api_key_id.is_not(None),
    )
    keys = {
        row.api_key_id: row
        for row in await session.execute(
            select(
                RequestLifecycle.api_key_id,
                *counts,
                _request_ids(outcome == "truncated").label("truncated_ids"),
                _request_ids(unanswered).label("unanswered_ids"),
            )
            .where(*window)
            .group_by(RequestLifecycle.api_key_id)
            .having(settled >= OUTCOME_RATE_MIN_SETTLED)
        )
    }
    if not keys:
        return []
    models: dict[UUID, list[Any]] = {}
    model = shown_model(RequestLifecycle.requested_model)
    for row in await session.execute(
        select(RequestLifecycle.api_key_id, model.label("model"), *counts)
        .where(*window, RequestLifecycle.api_key_id.in_(list(keys)))
        .group_by(RequestLifecycle.api_key_id, model)
        .order_by(RequestLifecycle.api_key_id, settled.desc(), model)
    ):
        models.setdefault(row.api_key_id, []).append(row)
    detections = []
    for key_id, row in sorted(keys.items()):
        top = models[key_id][:EVIDENCE_MODELS_PER_KEY]
        unanswered_count = row.refused + row.filtered + row.empty
        for rule_id, count, threshold, ids, fields, ended in (
            (
                TRUNCATION_RATE,
                row.truncated,
                TRUNCATION_RATE_THRESHOLD,
                row.truncated_ids,
                ("truncated",),
                "stopped at the output limit",
            ),
            (
                REFUSAL_RATE,
                unanswered_count,
                REFUSAL_RATE_THRESHOLD,
                row.unanswered_ids,
                ("refused", "filtered", "empty"),
                "were refused, filtered or empty",
            ),
        ):
            rate = Decimal(count) / row.settled
            if rate < threshold:
                continue
            detections.append(
                Detection(
                    rule_id=rule_id,
                    subject_key=f"api_key:{key_id}",
                    subject={"api_key_id": str(key_id)},
                    evidence={
                        "window_hours": OUTCOME_RATE_WINDOW_HOURS,
                        "settled_requests": row.settled,
                        **{field: getattr(row, field) for field in fields},
                        "rate": str(round(rate, 4)),
                        "threshold_rate": str(threshold),
                        "models": [
                            {
                                "model": item.model,
                                "settled": item.settled,
                                **{field: getattr(item, field) for field in fields},
                            }
                            for item in top
                        ],
                        "request_ids": list(ids or []),
                    },
                    impact={"cost_usd": None, "requests": count},
                )
            )
    return detections


def _quality_scope(tenant_id: UUID, now: datetime) -> tuple[Any, ...]:
    return (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= now - timedelta(hours=QUALITY_WINDOW_HOURS),
        RequestLifecycle.started_at <= now,
        RequestLifecycle.api_key_id.is_not(None),
    )


def _per_key(rows: Any) -> dict[UUID, list[Any]]:
    keys: dict[UUID, list[Any]] = {}
    for row in rows:
        keys.setdefault(row.api_key_id, []).append(row)
    return keys


def _quality_finding(
    rule_id: str,
    key_id: UUID,
    total: tuple[str, int],
    affected: tuple[str, int],
    minimum: int,
    threshold: Decimal,
    request_ids: list[str],
    **evidence: Any,
) -> Detection | None:
    """A finding for one API key once enough answers were read and enough went wrong."""
    (total_name, total_count), (affected_name, affected_count) = total, affected
    if total_count < minimum:
        return None
    rate = Decimal(affected_count) / total_count
    if rate < threshold:
        return None
    return Detection(
        rule_id=rule_id,
        subject_key=f"api_key:{key_id}",
        subject={"api_key_id": str(key_id)},
        evidence={
            "window_hours": QUALITY_WINDOW_HOURS,
            total_name: total_count,
            affected_name: affected_count,
            "rate": str(round(rate, 4)),
            "threshold_rate": str(threshold),
            **evidence,
            "request_ids": request_ids[:EVIDENCE_REQUEST_IDS],
        },
        impact={"cost_usd": None, "requests": affected_count},
    )


async def _language_drift(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    language = RequestLifecycle.lifecycle_metadata["response_analysis"]["language"]
    asked, answered = language["request"].as_string(), language["answer"].as_string()
    drift = answered == "en"
    prompt = RequestLifecycle.lifecycle_metadata["system_prompt_hash"].as_string()
    model = shown_model(RequestLifecycle.requested_model)
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            model.label("model"),
            func.count().label("analysed"),
            func.count().filter(drift).label("drifts"),
            _request_ids(drift).label("request_ids"),
            func.array_agg(distinct(prompt))
            .filter(drift & prompt.is_not(None))
            .label("prompts"),
        )
        .where(
            *_quality_scope(tenant_id, now),
            asked == "tr",
            answered.in_(("tr", "en")),
        )
        .group_by(RequestLifecycle.api_key_id, model)
    )
    detections = []
    for key_id, groups in sorted(_per_key(rows).items()):
        groups.sort(key=lambda row: (-row.analysed, row.model or ""))
        prompts = {
            value
            for row in groups
            for value in row.prompts or ()
            if _PROMPT_HASH.fullmatch(value)
        }
        found = _quality_finding(
            LANGUAGE_DRIFT,
            key_id,
            ("analysed_requests", sum(row.analysed for row in groups)),
            ("drifts", sum(row.drifts for row in groups)),
            LANGUAGE_DRIFT_MIN_REQUESTS,
            LANGUAGE_DRIFT_THRESHOLD,
            [value for row in groups for value in row.request_ids or ()],
            models=[
                {"model": row.model, "analysed": row.analysed, "drifts": row.drifts}
                for row in groups[:EVIDENCE_MODELS_PER_KEY]
            ],
            prompt_versions=sorted(prompts)[:EVIDENCE_PROMPT_VERSIONS],
        )
        if found is not None:
            detections.append(found)
    return detections


async def _schema_errors(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    schema = RequestLifecycle.lifecycle_metadata["response_analysis"]["schema"]
    expected = schema["expected"].as_string()
    invalid = schema["valid"].as_boolean().is_(False)
    outcome = RequestLifecycle.lifecycle_metadata["completion_outcome"].as_string()
    model = shown_model(RequestLifecycle.requested_model)
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            model.label("model"),
            expected.label("expected"),
            func.count().label("checked"),
            func.count().filter(invalid).label("invalid"),
            _request_ids(invalid).label("request_ids"),
        )
        .where(
            *_quality_scope(tenant_id, now),
            expected.in_(SCHEMA_KINDS),
            schema["valid"].as_boolean().is_not(None),
            schema["unsupported"].as_boolean().is_not(True),
            # A truncated answer is cut JSON: gateway.truncation_rate covers it.
            outcome == "complete",
        )
        .group_by(RequestLifecycle.api_key_id, model, expected)
    )
    detections = []
    for key_id, groups in sorted(_per_key(rows).items()):
        models: dict[str, list[int]] = {}
        kinds: dict[str, int] = {}
        for row in groups:
            counted = models.setdefault(row.model, [0, 0])
            counted[0] += row.checked
            counted[1] += row.invalid
            for name, value in (("checked", row.checked), ("invalid", row.invalid)):
                field = f"{name}_{row.expected}"
                kinds[field] = kinds.get(field, 0) + value
        ranked = sorted(models.items(), key=lambda item: (-item[1][0], item[0] or ""))
        found = _quality_finding(
            SCHEMA_ERRORS,
            key_id,
            ("checked_requests", sum(row.checked for row in groups)),
            ("invalid", sum(row.invalid for row in groups)),
            SCHEMA_ERRORS_MIN_CHECKED,
            SCHEMA_ERRORS_THRESHOLD,
            [
                value
                for row in sorted(groups, key=lambda row: -row.invalid)
                for value in row.request_ids or ()
            ],
            **dict(sorted(kinds.items())),
            models=[
                {"model": name, "checked": counts[0], "invalid": counts[1]}
                for name, counts in ranked[:EVIDENCE_MODELS_PER_KEY]
            ],
        )
        if found is not None:
            detections.append(found)
    return detections


async def _soft_refusals(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    refusal = RequestLifecycle.lifecycle_metadata["response_analysis"]["refusal"]
    soft = refusal["soft_refusal"].as_boolean()
    marker = refusal["marker"].as_string()
    outcome = RequestLifecycle.lifecycle_metadata["completion_outcome"].as_string()
    model = shown_model(RequestLifecycle.requested_model)
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            model.label("model"),
            marker.label("marker"),
            func.count().label("analysed"),
            func.count().filter(soft.is_(True)).label("refused"),
            _request_ids(soft.is_(True)).label("request_ids"),
        )
        .where(
            *_quality_scope(tenant_id, now),
            soft.is_not(None),
            outcome == "complete",
        )
        .group_by(RequestLifecycle.api_key_id, model, marker)
    )
    detections = []
    for key_id, groups in sorted(_per_key(rows).items()):
        models: dict[str, list[int]] = {}
        markers: dict[str, int] = {}
        for row in groups:
            counted = models.setdefault(row.model, [0, 0])
            counted[0] += row.analysed
            counted[1] += row.refused
            # Marker ids are the analyzer's fixed vocabulary; anything else is dropped.
            if row.refused and row.marker and _MARKER_ID.fullmatch(row.marker):
                name = f"marker_{row.marker.replace('.', '_')}"
                markers[name] = markers.get(name, 0) + row.refused
        ranked = sorted(models.items(), key=lambda item: (-item[1][0], item[0] or ""))
        top_markers = sorted(markers.items(), key=lambda item: (-item[1], item[0]))
        found = _quality_finding(
            SOFT_REFUSALS,
            key_id,
            ("analysed_requests", sum(row.analysed for row in groups)),
            ("soft_refusals", sum(row.refused for row in groups)),
            SOFT_REFUSAL_MIN_ANALYSED,
            SOFT_REFUSAL_THRESHOLD,
            [
                value
                for row in sorted(groups, key=lambda row: -row.refused)
                for value in row.request_ids or ()
            ],
            **dict(top_markers[:EVIDENCE_MARKERS]),
            models=[
                {"model": name, "analysed": counts[0], "soft_refusals": counts[1]}
                for name, counts in ranked[:EVIDENCE_MODELS_PER_KEY]
            ],
        )
        if found is not None:
            detections.append(found)
    return detections


# Per part kind, the record fields that judge it (a median at or over its limit
# crosses) and the characters the kind adds to a request.
_OVERSIZED_KINDS: dict[str, tuple[tuple[tuple[str, str, int], ...], str]] = {
    "tool_definitions": (
        (
            (
                "tool_definitions",
                "tool_definition_chars",
                OVERSIZED_TOOL_DEFINITION_CHARS,
            ),
        ),
        "tool_definition_chars",
    ),
    "history": (
        (
            ("history_messages", "message_count", OVERSIZED_HISTORY_MESSAGES),
            ("history_chars", "history_chars", OVERSIZED_HISTORY_CHARS),
        ),
        "history_chars",
    ),
    "large_part": (
        (("large_part", "largest_part_chars", OVERSIZED_LARGEST_PART_CHARS),),
        "largest_part_chars",
    ),
}


def _shape(field: str) -> Any:
    shape = RequestLifecycle.lifecycle_metadata["response_analysis"]["shape"]
    return cast(shape[field].as_string(), Integer)


def _shape_window(tenant_id: UUID, start: datetime, now: datetime) -> tuple[Any, ...]:
    return (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start,
        RequestLifecycle.started_at <= now,
        RequestLifecycle.api_key_id.is_not(None),
        RequestLifecycle.lifecycle_metadata["response_analysis"].has_key("shape"),
    )


async def _oversized_parts(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    window = _shape_window(tenant_id, now - timedelta(hours=WASTE_WINDOW_HOURS), now)
    fields = sorted(
        {field for checks, _ in _OVERSIZED_KINDS.values() for _, field, _ in checks}
    )
    keys = (
        await session.execute(
            select(
                RequestLifecycle.api_key_id,
                func.count().label("analysed"),
                *(
                    func.percentile_cont(share)
                    .within_group(_shape(field))
                    .label(f"{field}_{label}")
                    for field in fields
                    for share, label in ((0.5, "median"), (0.95, "p95"))
                ),
            )
            .where(*window)
            .group_by(RequestLifecycle.api_key_id)
            .having(func.count() >= OVERSIZED_MIN_REQUESTS)
        )
    ).all()
    detections = []
    for row in keys:
        crossed = [
            (checks, characters)
            for checks, characters in _OVERSIZED_KINDS.values()
            if any(
                getattr(row, f"{field}_median") >= limit for _, field, limit in checks
            )
        ]
        if not crossed:
            continue
        # A request counts once it is over a crossed kind's limit, with that kind's characters.
        over = [
            (
                or_(*(_shape(field) >= limit for _, field, limit in checks)),
                _shape(characters),
            )
            for checks, characters in crossed
        ]
        any_over = or_(*(condition for condition, _ in over))
        added = reduce(
            operator.add,
            (case((condition, size), else_=0) for condition, size in over),
        )
        requests, characters, request_ids = (
            await session.execute(
                select(
                    func.count().filter(any_over),
                    func.coalesce(func.sum(added), 0),
                    _request_ids(any_over, started_at=added.desc()),
                ).where(*window, RequestLifecycle.api_key_id == row.api_key_id)
            )
        ).one()
        detections.append(
            Detection(
                rule_id=OVERSIZED_PARTS,
                subject_key=f"api_key:{row.api_key_id}",
                subject={"api_key_id": str(row.api_key_id)},
                evidence={
                    "window_hours": WASTE_WINDOW_HOURS,
                    "analysed_requests": row.analysed,
                    "crossed_kinds": len(crossed),
                    **{
                        f"{name}_{label}": round(getattr(row, f"{field}_{label}"))
                        for checks, _ in crossed
                        for name, field, _ in checks
                        for label in ("median", "p95")
                    },
                    "tokens_estimated": True,
                    "request_ids": list(request_ids or []),
                },
                # Characters over four, the meter's estimate. No money: tool
                # definitions and early history are usually the cached prefix.
                impact={
                    "cost_usd": None,
                    "requests": requests,
                    "tokens": int(characters) // 4,
                },
            )
        )
    return detections


# The offer counts per key and tool, with the key's offering requests and the
# tool names its answers called, for keys that offered tools often enough and
# called at least one.
_DEAD_TOOLS = text(
    """
    WITH key_rows AS (
        -- Anything but an array reads as none, so a malformed row cannot fail the query.
        SELECT api_key_id,
               CASE WHEN jsonb_typeof(metadata -> 'response_analysis' -> 'shape'
                                      -> 'tools_offered') = 'array'
                    THEN metadata -> 'response_analysis' -> 'shape' -> 'tools_offered'
                    ELSE '[]'::jsonb END AS offered,
               CASE WHEN jsonb_typeof(metadata -> 'tool_call_names') = 'array'
                    THEN metadata -> 'tool_call_names' ELSE '[]'::jsonb END AS called
        FROM request_lifecycle
        WHERE organization_id = :tenant_id
          AND started_at >= :start AND started_at <= :now
          AND api_key_id IS NOT NULL
    ),
    offering AS (
        SELECT api_key_id, count(*) AS offering
        FROM key_rows
        WHERE jsonb_array_length(offered) > 0
        GROUP BY api_key_id
        HAVING count(*) >= :minimum
    ),
    calls AS (
        SELECT api_key_id, array_agg(DISTINCT name) AS names
        FROM key_rows, jsonb_array_elements_text(called) AS name
        GROUP BY api_key_id
    )
    SELECT key_rows.api_key_id, tool, count(*) AS offers, offering.offering,
           calls.names AS called
    FROM key_rows
    JOIN offering ON offering.api_key_id = key_rows.api_key_id
    JOIN calls ON calls.api_key_id = key_rows.api_key_id,
         jsonb_array_elements_text(key_rows.offered) AS tool
    GROUP BY key_rows.api_key_id, tool, offering.offering, calls.names
    ORDER BY key_rows.api_key_id, offers DESC, tool
    """
)
# When each organization's dead tools are next due, in this worker's memory as
# budgets keep theirs: a restart evaluates again, which refreshes the same findings.
_dead_tools_due: dict[UUID, datetime] = {}


async def _dead_tools(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    if now < _dead_tools_due.get(tenant_id, now):
        return []
    start = now - timedelta(days=DEAD_TOOLS_WINDOW_DAYS)
    keys: dict[UUID, list[Any]] = {}
    for row in await session.execute(
        _DEAD_TOOLS,
        {
            "tenant_id": tenant_id,
            "start": start,
            "now": now,
            "minimum": DEAD_TOOLS_MIN_REQUESTS,
        },
    ):
        keys.setdefault(row.api_key_id, []).append(row)
    _dead_tools_due[tenant_id] = now + timedelta(hours=DEAD_TOOLS_EVALUATION_HOURS)
    detections = []
    for key_id, tools in keys.items():
        called = set(tools[0].called)
        offering = tools[0].offering
        # A Responses built-in tool is called as <name>_call.
        dead = [
            row
            for row in tools
            if row.offers >= offering * DEAD_TOOLS_MIN_OFFER_SHARE
            and row.tool not in called
            and f"{row.tool}_call" not in called
        ][:EVIDENCE_DEAD_TOOLS]
        if not dead:
            continue
        offered = RequestLifecycle.lifecycle_metadata["response_analysis"]["shape"][
            "tools_offered"
        ]
        requests = await session.scalar(
            select(func.count()).where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= start,
                RequestLifecycle.started_at <= now,
                RequestLifecycle.api_key_id == key_id,
                offered.has_any(array([row.tool for row in dead])),
            )
        )
        detections.append(
            Detection(
                rule_id=DEAD_TOOLS,
                subject_key=f"api_key:{key_id}",
                subject={"api_key_id": str(key_id)},
                evidence={
                    "window_days": DEAD_TOOLS_WINDOW_DAYS,
                    "offering_requests": offering,
                    "dead_tools": len(dead),
                    "called_tools": len(called),
                    # Allowlisted tool names (S37) stay in the stored row only.
                    "tools": [
                        {"name": row.tool[:64], "offered": row.offers} for row in dead
                    ],
                },
                impact={"cost_usd": None, "requests": requests},
            )
        )
    return detections


async def _cache_order_churn(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    shape = RequestLifecycle.lifecycle_metadata["response_analysis"]["shape"]
    tool_set, order = (
        shape["tools_set_digest"].as_string(),
        shape["tools_order_digest"].as_string(),
    )
    # A log row without the field counts as no cache read.
    cached = (
        func.coalesce(
            cast(RequestLog.details["cached_input_tokens"].as_string(), Integer), 0
        )
        > 0
    )
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            tool_set.label("tool_set"),
            func.count().label("requests"),
            func.count().filter(cached).label("cache_reads"),
            func.array_agg(distinct(RequestLifecycle.provider)).label("providers"),
            _request_ids(true()).label("request_ids"),
        )
        .join(
            RequestLog,
            (RequestLog.organization_id == RequestLifecycle.organization_id)
            & (RequestLog.request_id == RequestLifecycle.request_id),
        )
        .where(
            *_shape_window(tenant_id, now - timedelta(hours=WASTE_WINDOW_HOURS), now),
            _shape("tool_count") >= 2,
            RequestLog.prompt_tokens >= CACHE_CHURN_MIN_PROMPT_TOKENS,
            tool_set.is_not(None),
            order.is_not(None),
        )
        .group_by(RequestLifecycle.api_key_id, tool_set, order)
    )
    sets: dict[tuple[UUID, str], list[Any]] = {}
    for row in rows:
        sets.setdefault((row.api_key_id, row.tool_set), []).append(row)
    churned: dict[UUID, list[dict[str, Any]]] = {}
    for (key_id, _), orders in sets.items():
        requests = sum(row.requests for row in orders)
        reads = sum(row.cache_reads for row in orders)
        dominant = max(row.requests for row in orders)
        if (
            requests >= CACHE_CHURN_MIN_REQUESTS
            and len(orders) >= 2
            and Decimal(dominant) / requests < CACHE_CHURN_MAX_DOMINANT_SHARE
            and Decimal(reads) / requests < CACHE_CHURN_MAX_CACHE_READ_SHARE
        ):
            churned.setdefault(key_id, []).append(
                {
                    "requests": requests,
                    "orders": len(orders),
                    "requests_per_order": sorted(
                        (row.requests for row in orders), reverse=True
                    ),
                    "cache_read_share": str(round(Decimal(reads) / requests, 4)),
                    "providers": sorted(
                        {
                            provider
                            for row in orders
                            for provider in row.providers or ()
                            if provider in PROVIDERS
                        }
                    ),
                    "request_ids": [
                        value for row in orders for value in row.request_ids or ()
                    ],
                }
            )
    detections = []
    for key_id, found in sorted(churned.items()):
        found.sort(key=lambda item: -item["requests"])
        largest = found[0]
        detections.append(
            Detection(
                rule_id=CACHE_ORDER_CHURN,
                subject_key=f"api_key:{key_id}",
                subject={"api_key_id": str(key_id)},
                evidence={
                    "window_hours": WASTE_WINDOW_HOURS,
                    "tool_sets": len(found),
                    "churned_requests": sum(item["requests"] for item in found),
                    "orders": largest["orders"],
                    "cache_read_share": largest["cache_read_share"],
                    "sets": [
                        {
                            key: value
                            for key, value in item.items()
                            if key != "request_ids"
                        }
                        for item in found[:EVIDENCE_TOOL_SETS]
                    ],
                    "request_ids": [
                        value for item in found for value in item["request_ids"]
                    ][:EVIDENCE_REQUEST_IDS],
                },
                impact={
                    "cost_usd": None,
                    "requests": sum(item["requests"] for item in found),
                },
            )
        )
    return detections


# A registry deployment's requests with their idle gap (seconds since the previous
# request of the same deployment; a lookback day earlier counts, and no previous
# request is a gap of the whole lookback) and their first byte (TTFT for a stream,
# provider latency for JSON). Warm requests' median first byte makes a cold start
# relative: a gap of at least the idle threshold, and a timeout or a first byte of
# at least max(minimum, factor x warm median).
_DEPLOYMENT_REQUESTS = """
    rows AS (
        SELECT metadata ->> 'deployment_id' AS deployment_id, request_id, started_at,
               stream, status,
               {first_byte} AS first_byte,
               coalesce(EXTRACT(EPOCH FROM started_at - lag(started_at) OVER (
                   PARTITION BY metadata ->> 'deployment_id' ORDER BY started_at
               )), :lookback_seconds) AS gap
        FROM request_lifecycle
        WHERE organization_id = :tenant_id
          AND started_at >= CAST(:lookback AS timestamptz)
          AND started_at <= CAST(:now AS timestamptz)
          AND metadata ->> 'deployment_id' IS NOT NULL
    ),
    windowed AS (
        SELECT * FROM rows WHERE started_at >= CAST(:start AS timestamptz)
    ),
    warm AS (
        SELECT deployment_id,
               percentile_cont(0.5) WITHIN GROUP (ORDER BY first_byte) AS first_byte
        FROM windowed WHERE gap < :idle_seconds AND first_byte IS NOT NULL
        GROUP BY deployment_id
    ),
    classified AS (
        SELECT windowed.*, warm.first_byte AS warm_first_byte,
               windowed.gap >= :idle_seconds AND (
                   windowed.status = 'timeout'
                   OR windowed.first_byte >= greatest(
                       :min_first_byte, :factor * coalesce(warm.first_byte, 0)
                   )
               ) AS cold
        FROM windowed LEFT JOIN warm USING (deployment_id)
    )
"""
_COLD_STARTS = text(
    "WITH"
    + _DEPLOYMENT_REQUESTS.format(first_byte=FIRST_BYTE_SQL.format(t=""))
    + """
    SELECT deployment_id,
           count(*) AS cold_starts,
           count(*) FILTER (WHERE status = 'timeout') AS timeouts,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY gap) AS gap_seconds,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY first_byte) AS cold_first_byte,
           max(warm_first_byte) AS warm_first_byte,
           (array_agg(request_id ORDER BY started_at))[1:20] AS request_ids
    FROM classified
    WHERE cold
    GROUP BY deployment_id
    HAVING count(*) >= :min_events
    """
)


def _deployment_window(tenant_id: UUID, start: datetime, now: datetime) -> dict:
    return {
        "tenant_id": tenant_id,
        "lookback": start - COLD_START_LOOKBACK,
        "lookback_seconds": COLD_START_LOOKBACK.total_seconds(),
        "start": start,
        "now": now,
        "idle_seconds": COLD_START_MIN_IDLE_SECONDS,
        "min_first_byte": COLD_START_MIN_FIRST_BYTE_MS,
        "factor": COLD_START_LATENCY_FACTOR,
    }


async def _cold_starts(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    rows = await session.execute(
        _COLD_STARTS,
        {
            **_deployment_window(
                tenant_id, now - timedelta(hours=COLD_START_WINDOW_HOURS), now
            ),
            "min_events": COLD_START_MIN_EVENTS,
        },
    )
    return [
        Detection(
            rule_id=COLD_START,
            subject_key=f"deployment:{row.deployment_id}",
            subject={"deployment_id": row.deployment_id},
            evidence={
                "window_hours": COLD_START_WINDOW_HOURS,
                "cold_starts": row.cold_starts,
                "timeouts": row.timeouts,
                "median_gap_seconds": round(row.gap_seconds),
                "cold_first_byte_ms": _ms(row.cold_first_byte),
                "warm_first_byte_ms": _ms(row.warm_first_byte),
                "request_ids": list(row.request_ids or []),
            },
            impact={"cost_usd": None, "requests": row.cold_starts},
        )
        for row in rows
    ]


def _ms(value: float | None) -> int | None:
    return None if value is None else round(value)


# Per deployment and hour of the window: streams, their p95 TTFT without the cold
# starts, and the most streams in flight at once; and the 7-day baseline before.
_QUEUEING = text(
    "WITH"
    + _DEPLOYMENT_REQUESTS.format(first_byte=FIRST_BYTE_SQL.format(t=""))
    + """,
    baseline AS (
        SELECT metadata ->> 'deployment_id' AS deployment_id,
               percentile_cont(0.5) WITHIN GROUP (
                   ORDER BY (metadata ->> 'ttft_ms')::float
               ) AS ttft
        FROM request_lifecycle
        WHERE organization_id = :tenant_id
          AND started_at >= CAST(:baseline_start AS timestamptz)
          AND started_at < CAST(:start AS timestamptz)
          AND stream AND metadata ->> 'deployment_id' IS NOT NULL
          AND metadata ->> 'ttft_ms' IS NOT NULL
        GROUP BY metadata ->> 'deployment_id'
        HAVING count(*) >= :min_baseline
    ),
    hours AS (
        SELECT deployment_id, date_trunc('hour', started_at AT TIME ZONE 'UTC') AS hour,
               count(*) AS streams,
               percentile_cont(0.95) WITHIN GROUP (ORDER BY first_byte)
                   FILTER (WHERE NOT cold) AS ttft_p95,
               (array_agg(request_id ORDER BY first_byte DESC NULLS LAST))[1:20]
                   AS request_ids
        FROM classified
        WHERE stream AND deployment_id IN (SELECT deployment_id FROM baseline)
        GROUP BY deployment_id, date_trunc('hour', started_at AT TIME ZONE 'UTC')
        HAVING count(*) >= :min_hour_streams
    ),
    spans AS (
        SELECT l.metadata ->> 'deployment_id' AS deployment_id,
               l.provider_started_at AT TIME ZONE 'UTC' AS s,
               coalesce(l.completed_at, CAST(:now AS timestamptz)) AT TIME ZONE 'UTC' AS e
        FROM request_lifecycle l
        WHERE l.organization_id = :tenant_id
          AND l.started_at >= CAST(:lookback AS timestamptz)
          AND l.started_at <= CAST(:now AS timestamptz)
          AND l.stream AND l.provider_started_at IS NOT NULL
          AND l.metadata ->> 'deployment_id' IN (SELECT deployment_id FROM hours)
    ),
    clipped AS (
        SELECT hours.deployment_id AS grp, hours.hour AS bucket,
               greatest(spans.s, hours.hour) AS s,
               least(spans.e, hours.hour + interval '1 hour') AS e
        FROM hours JOIN spans
          ON spans.deployment_id = hours.deployment_id
         AND spans.s < hours.hour + interval '1 hour' AND spans.e > hours.hour
    ),"""
    + SWEEP_SQL
    + """
    SELECT hours.deployment_id, hours.hour, hours.streams, hours.ttft_p95,
           coalesce(peaks.peak, 0) AS peak, baseline.ttft AS baseline,
           hours.request_ids
    FROM hours
    JOIN baseline USING (deployment_id)
    LEFT JOIN peaks ON peaks.grp = hours.deployment_id AND peaks.bucket = hours.hour
    WHERE hours.ttft_p95 >= :factor_queue * baseline.ttft
      AND coalesce(peaks.peak, 0) >= :min_peak
    ORDER BY hours.deployment_id, hours.hour
    """
)


async def _queueing(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    start = now - timedelta(hours=QUEUEING_WINDOW_HOURS)
    deployments: dict[str, list[Any]] = {}
    for row in await session.execute(
        _QUEUEING,
        {
            **_deployment_window(tenant_id, start, now),
            "baseline_start": start - timedelta(days=QUEUEING_BASELINE_DAYS),
            "min_baseline": QUEUEING_MIN_BASELINE_STREAMS,
            "min_hour_streams": QUEUEING_MIN_HOUR_STREAMS,
            "factor_queue": QUEUEING_FACTOR,
            "min_peak": QUEUEING_MIN_PEAK_CONCURRENCY,
        },
    ):
        deployments.setdefault(row.deployment_id, []).append(row)
    return [
        Detection(
            rule_id=QUEUEING,
            subject_key=f"deployment:{deployment_id}",
            subject={"deployment_id": deployment_id},
            evidence={
                "window_hours": QUEUEING_WINDOW_HOURS,
                "congested_hours": len(hours),
                "baseline_ttft_ms": _ms(hours[0].baseline),
                "worst_ttft_p95_ms": max(_ms(row.ttft_p95) or 0 for row in hours),
                "peak_concurrency": max(row.peak for row in hours),
                "hours": [
                    {
                        "hour": row.hour.replace(tzinfo=timezone.utc).isoformat(),
                        "ttft_p95_ms": _ms(row.ttft_p95),
                        "streams": row.streams,
                        "peak_concurrency": row.peak,
                    }
                    for row in hours
                ],
                "request_ids": [
                    value for row in hours for value in row.request_ids or ()
                ][:EVIDENCE_REQUEST_IDS],
            },
            impact={"cost_usd": None, "requests": sum(row.streams for row in hours)},
        )
        for deployment_id, hours in sorted(deployments.items())
        if len(hours) >= QUEUEING_MIN_HOURS
    ]


def _litellm_rows(tenant_id: UUID, end: datetime, window: timedelta) -> tuple[Any, ...]:
    record = ExternalUsageRecord
    return (
        record.organization_id == tenant_id,
        record.source == "litellm",
        record.started_at > end - window,
        record.started_at <= end,
    )


def _litellm_model() -> Any:
    return func.coalesce(ExternalUsageRecord.model, ExternalUsageRecord.model_group)


def _litellm_impact(condition: Any = true()) -> tuple[Any, ...]:
    record = ExternalUsageRecord
    return (
        func.count().filter(condition).label("requests"),
        func.coalesce(
            func.sum(
                func.coalesce(record.prompt_tokens, 0)
                + func.coalesce(record.completion_tokens, 0)
            ).filter(condition),
            0,
        ).label("tokens"),
        func.sum(record.cost_usd).filter(condition).label("cost"),
        _request_ids(condition, record.source_request_id, record.started_at).label(
            "request_ids"
        ),
    )


def _litellm_detection(
    rule_id: str, subject: dict[str, str], row: Any, evidence: dict[str, Any]
) -> Detection:
    # The source's own cost, labelled so; never added to shim's spend.
    return Detection(
        rule_id=rule_id,
        subject_key=next(iter(subject.values())),
        subject=subject,
        evidence={
            **evidence,
            "request_ids": [
                request_id
                for request_id in row.request_ids or []
                if _EVIDENCE_ID.fullmatch(request_id)
            ],
        },
        impact={
            "requests": row.requests,
            "tokens": int(row.tokens),
            "cost_usd": None if row.cost is None else str(row.cost),
            "cost_source": "litellm",
        },
    )


async def _litellm_unregistered_models(
    session: AsyncSession, tenant_id: UUID, end: datetime
) -> list[Detection]:
    deployments = (
        await session.execute(
            select(ModelDeployment.alias, ModelDeployment.upstream_model).where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.enabled.is_(True),
            )
        )
    ).all()
    if not deployments:
        return []
    names = {name for row in deployments for name in row}
    record, model = ExternalUsageRecord, _litellm_model()
    rows = await session.execute(
        select(model.label("model"), *_litellm_impact())
        .where(
            *_litellm_rows(
                tenant_id, end, timedelta(days=LITELLM_UNREGISTERED_WINDOW_DAYS)
            ),
            model.is_not(None),
            or_(record.model.is_(None), not_(record.model.in_(names))),
            or_(record.model_group.is_(None), not_(record.model_group.in_(names))),
        )
        .group_by(model)
        .having(func.count() >= LITELLM_UNREGISTERED_MIN_REQUESTS)
        .order_by(model)
    )
    return [
        _litellm_detection(
            LITELLM_UNREGISTERED_MODEL,
            {"model": row.model[:_SUBJECT_ID_LENGTH]},
            row,
            {
                "requests": row.requests,
                "window_days": LITELLM_UNREGISTERED_WINDOW_DAYS,
                "threshold": LITELLM_UNREGISTERED_MIN_REQUESTS,
            },
        )
        for row in rows
    ]


async def _litellm_error_rates(
    session: AsyncSession, tenant_id: UUID, end: datetime
) -> list[Detection]:
    record, model = ExternalUsageRecord, _litellm_model()
    failed = and_(record.status.is_not(None), record.status != "success")
    failures = func.count().filter(failed)
    rows = await session.execute(
        select(
            model.label("model"),
            failures.label("failed"),
            func.count().label("all_requests"),
            *_litellm_impact(failed),
        )
        .where(
            *_litellm_rows(tenant_id, end, timedelta(hours=LITELLM_RATE_WINDOW_HOURS)),
            model.is_not(None),
        )
        .group_by(model)
        .having(
            func.count() >= LITELLM_ERROR_MIN_REQUESTS,
            cast(failures, Numeric) >= LITELLM_ERROR_THRESHOLD * func.count(),
        )
        .order_by(model)
    )
    return [
        _litellm_detection(
            LITELLM_ERROR_RATE,
            {"model": row.model[:_SUBJECT_ID_LENGTH]},
            row,
            {
                "requests": row.all_requests,
                "failed_requests": row.failed,
                "failure_share": str(round(Decimal(row.failed) / row.all_requests, 4)),
                "threshold": str(LITELLM_ERROR_THRESHOLD),
                "window_hours": LITELLM_RATE_WINDOW_HOURS,
            },
        )
        for row in rows
    ]


async def _litellm_slow_first_tokens(
    session: AsyncSession, tenant_id: UUID, end: datetime
) -> list[Detection]:
    record, model = ExternalUsageRecord, _litellm_model()
    measured = record.ttft_ms.is_not(None)
    p95 = func.percentile_cont(0.95).within_group(record.ttft_ms)
    rows = await session.execute(
        select(model.label("model"), p95.label("p95"), *_litellm_impact(measured))
        .where(
            *_litellm_rows(tenant_id, end, timedelta(hours=LITELLM_RATE_WINDOW_HOURS)),
            model.is_not(None),
            measured,
        )
        .group_by(model)
        .having(func.count() >= LITELLM_SLOW_MIN_ROWS, p95 >= LITELLM_SLOW_P95_MS)
        .order_by(model)
    )
    return [
        _litellm_detection(
            LITELLM_SLOW_FIRST_TOKEN,
            {"model": row.model[:_SUBJECT_ID_LENGTH]},
            row,
            {
                "requests": row.requests,
                "ttft_ms_p95": round(row.p95),
                "threshold_ms": LITELLM_SLOW_P95_MS,
                "window_hours": LITELLM_RATE_WINDOW_HOURS,
            },
        )
        for row in rows
    ]


async def _litellm_retry_bursts(
    session: AsyncSession, tenant_id: UUID, end: datetime
) -> list[Detection]:
    record = ExternalUsageRecord
    bucket = func.date_bin(RETRY_BUCKET, record.started_at, _EPOCH)
    rows = await session.execute(
        select(
            record.source_key_hash,
            record.model,
            record.prompt_tokens,
            bucket.label("bucket"),
            *_litellm_impact(),
        )
        .where(
            *_litellm_rows(tenant_id, end, LITELLM_BURST_WINDOW),
            record.source_key_hash.is_not(None),
            record.prompt_tokens.is_not(None),
        )
        .group_by(record.source_key_hash, record.model, record.prompt_tokens, bucket)
        .having(func.count() >= RETRY_STORM_MIN_REQUESTS)
        .order_by(record.source_key_hash, func.count().desc(), bucket.desc())
    )
    worst: dict[str, Any] = {}
    for row in rows:
        worst.setdefault(row.source_key_hash, row)
    return [
        _litellm_detection(
            LITELLM_RETRY_BURST,
            {"litellm_key": f"litellm:{key_hash[:LITELLM_KEY_PREFIX]}"},
            row,
            {
                "window_start": row.bucket.isoformat(),
                "window_minutes": RETRY_BUCKET // timedelta(minutes=1),
                "repeated_requests": row.requests,
                "threshold": RETRY_STORM_MIN_REQUESTS,
                "prompt_tokens": row.prompt_tokens,
            },
        )
        for key_hash, row in worst.items()
    ]


async def evaluate_litellm(
    session: AsyncSession, tenant_id: UUID, *, end: datetime, import_id: UUID
) -> list[tuple[str, bool]]:
    """The litellm.* rules over a tenant's imported rows, the window ending at end.

    Imported data is history: the worker never runs these, an import does. Each
    rule id with whether its finding was opened (True) or updated.
    """
    now = datetime.now(timezone.utc)
    modes = await finding_modes(session, tenant_id)
    results = []
    for rule in (
        _litellm_unregistered_models,
        _litellm_error_rates,
        _litellm_slow_first_tokens,
        _litellm_retry_bursts,
    ):
        for detection in await rule(session, tenant_id, end):
            stamped = replace(
                detection, evidence={**detection.evidence, "import_id": str(import_id)}
            )
            opened = await upsert_detection(
                session, tenant_id, stamped, now=now, modes=modes
            )
            results.append((detection.rule_id, opened))
    return results


async def upsert_detection(
    session: AsyncSession,
    tenant_id: UUID,
    detection: Detection,
    *,
    now: datetime,
    modes: Mapping[str, Mode],
) -> bool:
    """One open finding per rule and subject; True when this opened it."""
    spec = RULES[detection.rule_id]
    statement = insert(Finding).values(
        organization_id=tenant_id,
        source=spec.SOURCE,
        rule_id=detection.rule_id,
        rule_version=RULE_VERSIONS.get(detection.rule_id, RULE_VERSION),
        subject_key=detection.subject_key,
        subject=detection.subject,
        title=spec.TITLE,
        summary=render(spec.SUMMARY["en"], measurements(detection.evidence)),
        severity_id=spec.SEVERITY_ID,
        first_seen_at=now,
        last_seen_at=now,
        evidence=detection.evidence,
        impact=detection.impact,
        remediation={
            **ladder_remediation(detection.rule_id, detection.subject, modes),
            "text": remediation_text(detection.rule_id, detection.evidence)["en"],
            "doc": spec.PLAYBOOK,
        },
    )
    return bool(
        await session.scalar(
            statement.on_conflict_do_update(
                index_elements=["organization_id", "rule_id", "subject_key"],
                index_where=Finding.status_id != STATUS_RESOLVED,
                set_={
                    "last_seen_at": now,
                    "occurrences": Finding.occurrences + 1,
                    "summary": statement.excluded.summary,
                    "evidence": statement.excluded.evidence,
                    "impact": statement.excluded.impact,
                    "rule_version": statement.excluded.rule_version,
                    "remediation": statement.excluded.remediation,
                    "updated_at": func.now(),
                },
            ).returning(literal_column("xmax = 0"))
        )
    )


async def evaluate_organization(
    session: AsyncSession, tenant_id: UUID, *, now: datetime
) -> list[Detection]:
    # Each rule and the rule ids it raises. A rule that fails is rolled back alone
    # and leaves its open findings as they are; the other rules still run.
    rules = (
        (_retry_storms, (RETRY_STORM,)),
        (_repeat_spend, (REPEAT_SPEND,)),
        (_deployments, (UNUSED_DEPLOYMENT, IDLE_INTERNAL_DEPLOYMENT)),
        (_unregistered_models, (UNREGISTERED_MODEL,)),
        (_byok_usage, (BYOK_USAGE,)),
        (_answer_quality, (ANSWER_QUALITY,)),
        (_outcome_rates, (TRUNCATION_RATE, REFUSAL_RATE)),
        (_language_drift, (LANGUAGE_DRIFT,)),
        (_schema_errors, (SCHEMA_ERRORS,)),
        (_soft_refusals, (SOFT_REFUSALS,)),
        (_oversized_parts, (OVERSIZED_PARTS,)),
        (_dead_tools, (DEAD_TOOLS,)),
        (_cache_order_churn, (CACHE_ORDER_CHURN,)),
        (_cold_starts, (COLD_START,)),
        (_queueing, (QUEUEING,)),
    )
    detections: list[Detection] = []
    failed: list[str] = []
    modes = await finding_modes(session, tenant_id)
    for rule, rule_ids in rules:
        try:
            async with session.begin_nested():
                found = await rule(session, tenant_id, now)
                for detection in found:
                    await upsert_detection(
                        session, tenant_id, detection, now=now, modes=modes
                    )
        except Exception as exc:
            failed += rule_ids
            logger.error(
                "Findings rule failed organization_id=%s rules=%s type=%s",
                tenant_id,
                ",".join(rule_ids),
                type(exc).__name__,
            )
        else:
            detections += found
    await apply_modes(session, tenant_id, modes)
    await session.execute(
        update(Finding)
        .where(
            Finding.organization_id == tenant_id,
            Finding.status_id != STATUS_RESOLVED,
            Finding.last_seen_at < now - AUTO_RESOLVE_AFTER,
            Finding.rule_id.not_in(failed),
        )
        .values(status_id=STATUS_RESOLVED, resolved_at=now, resolved_by="system")
    )
    return detections


async def evaluate_findings(
    session_factory: Callable[[], Any], *, now: datetime
) -> None:
    """Evaluate every rule for every active organization, one transaction each."""
    async with session_factory() as session:
        tenant_ids = (
            await session.scalars(
                select(Organization.id).where(Organization.archived_at.is_(None))
            )
        ).all()
    for tenant_id in tenant_ids:
        async with session_factory() as session:
            try:
                await evaluate_organization(session, tenant_id, now=now)
                await session.commit()
            except Exception as exc:
                await session.rollback()
                logger.error(
                    "Findings evaluation failed organization_id=%s type=%s",
                    tenant_id,
                    type(exc).__name__,
                )


_SUBJECT_KINDS = (
    ("api_key_id", "key"),
    ("litellm_key", "key"),
    ("deployment_id", "deployment"),
    ("model", "model"),
)
_STATUSES: dict[
    int,
    tuple[
        Literal["open", "resolved", "dismissed"],
        Literal["new", "in_progress", "suppressed", "resolved"],
    ],
] = {
    1: ("open", "new"),
    2: ("open", "in_progress"),
    3: ("dismissed", "suppressed"),
    4: ("resolved", "resolved"),
}


def _request_evidence(evidence: Mapping[str, Any]) -> list[str]:
    """Each shown pair as the repeat then the request it repeats, then the other ids."""

    paired = [
        request_id
        for pair in (evidence.get("pairs") or [])[:EVIDENCE_PAIRS]
        for request_id in (pair["repeat"], pair["previous"])
    ]
    rest = [i for i in evidence.get("request_ids") or [] if i not in paired]
    return paired + rest


def finding_from_row(row: Finding) -> FindingV1:
    """Total: a row this build cannot render keeps its stored English text.

    An unknown rule, a measurement its template lacks or a subject of a later kind
    degrades that one row, so a list or an export never fails on it.
    """

    status, status_detail = _STATUSES[row.status_id]
    common: dict[str, Any] = {
        "schema_version": "1",
        "id": str(row.id),
        "source": row.source,
        "rule_id": row.rule_id,
        "rule_version": row.rule_version,
        "severity": SEVERITIES[row.severity_id - 1],
        "status": status,
        "status_detail": status_detail,
        "window": FindingWindow(
            start=row.first_seen_at.astimezone(timezone.utc),
            end=row.last_seen_at.astimezone(timezone.utc),
        ),
        "occurrences": row.occurrences,
        "resolved_at": row.resolved_at and row.resolved_at.astimezone(timezone.utc),
        "resolved_by": row.resolved_by,
    }
    try:
        spec = RULES[row.rule_id]
        values = measurements(row.evidence)
        field, kind = next(item for item in _SUBJECT_KINDS if item[0] in row.subject)
        impact = row.impact or {}
        usd = impact.get("cost_usd")
        # A row written before modes existed reads as observe.
        mode = min(
            row.remediation.get("mode", "observe"), spec.MAX_MODE, key=MODES.index
        )
        return FindingV1(
            **common,
            title=spec.TITLE,
            summary=FindingText(
                en=render(spec.SUMMARY["en"], values),
                tr=render(spec.SUMMARY["tr"], values),
            ),
            subject=FindingSubject(kind=kind, id=str(row.subject[field])),
            evidence=[
                FindingEvidence(kind="request", id=request_id)
                for request_id in _request_evidence(row.evidence)
            ],
            measurements=values,
            impact=FindingImpact(
                requests=impact.get("requests"),
                tokens=impact.get("tokens"),
                usd=None if usd is None else format(Decimal(str(usd)), "f"),
                risk_class=spec.RISK_CLASS,
            ),
            remediation=FindingRemediation(
                mode=mode,
                max_mode=spec.MAX_MODE,
                action=None if mode == "observe" else row.remediation.get("action"),
                reversible=bool(row.remediation.get("reversible", spec.REVERSIBLE)),
                blast_radius=spec.BLAST_RADIUS,
                proof_after=None,
                text=FindingText(**remediation_text(row.rule_id, row.evidence)),
            ),
            playbook=row.remediation.get("doc") or spec.PLAYBOOK,
        )
    except (KeyError, IndexError, ValueError, StopIteration) as exc:
        logger.warning(
            "Finding degraded to the row's own text id=%s type=%s",
            row.id,
            type(exc).__name__,
        )
    stored = str(row.remediation.get("text") or row.title)[:500]
    return FindingV1(
        **common,
        title=row.title[:200],
        summary=FindingText(en=row.summary[:500], tr=row.summary[:500]),
        subject=FindingSubject(kind="tenant", id=str(row.organization_id)),
        evidence=[],
        measurements={},
        impact=FindingImpact(requests=None, tokens=None, usd=None, risk_class=None),
        remediation=FindingRemediation(
            mode="observe",
            max_mode="observe",
            action=None,
            reversible=row.remediation.get("reversible") is True,
            blast_radius="tenant",
            proof_after=None,
            text=FindingText(en=stored, tr=stored),
        ),
        playbook="ee/docs/FINDINGS.md#gateway-findings",
    )


def ocsf_detection_finding(row: Finding) -> dict[str, Any]:
    finding = finding_from_row(row)
    if finding.status == "resolved":
        activity_id = 3
    elif row.occurrences > 1 or finding.status_detail != "new":
        activity_id = 2
    else:
        activity_id = 1
    v1 = finding.model_dump(mode="json")
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": activity_id,
        "type_uid": 200400 + activity_id,
        "time": _epoch_ms(row.resolved_at or finding.window.end),
        "severity_id": SEVERITIES.index(finding.severity) + 1,
        "status_id": STATUS_IDS[finding.status_detail or "new"],
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "shim", "vendor_name": "shim"},
        },
        "finding_info": {
            "uid": finding.id,
            "title": finding.title,
            "desc": finding.summary.en,
            "first_seen_time": _epoch_ms(finding.window.start),
            "last_seen_time": _epoch_ms(finding.window.end),
        },
        "unmapped": {
            "schema_version": finding.schema_version,
            "summary_tr": finding.summary.tr,
            **{
                key: v1[key]
                for key in (
                    "rule_id",
                    "rule_version",
                    "subject",
                    "occurrences",
                    "evidence",
                    "measurements",
                    "impact",
                    "remediation",
                )
            },
        },
    }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)
