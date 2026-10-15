#!/usr/bin/env bash
# One entry point for the benchmarks in docs/BENCHMARKS.md. Run from the repository root.
#
#   scripts/bench/run_all.sh --all
#   scripts/bench/run_all.sh --corpus --detection --evasion   # section A
#   scripts/bench/run_all.sh --middleware --overhead          # section B1, needs an idle machine
#   scripts/bench/run_all.sh --savings --env path/to/.env   # section B2, spends < $2
#   scripts/bench/run_all.sh --report
#
# Results go to scripts/bench/results/<date>/ (BENCH_OUT overrides). Every run is kept.
set -euo pipefail

OUT=${BENCH_OUT:-scripts/bench/results/$(date +%Y-%m-%d)}
BASE=${SHIM_V030:-../bench-base}   # a checkout of v0.3.0 (ca6b2e9), next to this one
ENV_FILE=""
SPACY_MODEL=https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
COMPOSE=(docker compose -f scripts/bench/litellm/docker-compose.yml)
steps=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --all) steps=(corpus detection evasion middleware overhead savings report) ;;
    --env) ENV_FILE=$2; shift ;;
    --*) steps+=("${1#--}") ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[[ ${#steps[@]} -gt 0 ]] || { sed -n '2,10p' "$0"; exit 2; }
mkdir -p "$OUT/captures"
export CAPTURES=$PWD/$OUT/captures
py() { uv run --locked python -m "$@"; }

idle() {
  # Latency numbers are only published from an idle machine.
  local load
  load=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' || cut -d' ' -f1 /proc/loadavg)
  echo "load average: $load"
  if awk "BEGIN {exit !($load > 2)}" && [[ -z ${BENCH_ALLOW_BUSY:-} ]]; then
    echo "machine is busy; wait, or set BENCH_ALLOW_BUSY=1 for a run you will not publish" >&2
    exit 1
  fi
}

wait_http() {
  for _ in $(seq 1 120); do curl -sf -o /dev/null "$1" && return; sleep 2; done
  echo "$1 did not come up" >&2; exit 1
}

up() {
  "${COMPOSE[@]}" up -d --wait --wait-timeout 300 "$@"
}

down() { "${COMPOSE[@]}" down --remove-orphans; }

memory() {  # Images and memory after a load run: the deployment footprint.
  "${COMPOSE[@]}" images >> "$OUT/overhead-images.txt"
  docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' >> "$OUT/overhead-memory.txt"
}

litellm_up() {
  up presidio-analyzer presidio-anonymizer "$@" mock litellm
  wait_http http://127.0.0.1:4000/health/liveliness
}

score() {  # score <corpus file>
  local corpus=$1 name
  name=$(basename "$corpus" .jsonl)
  py scripts.bench.pii_score run --system shim --corpus "$corpus" --out "$OUT/$name-shim-main.jsonl"
  py scripts.bench.pii_score run --system shim --names --corpus "$corpus" --out "$OUT/$name-shim-main-names.jsonl"
  uv run --locked --project "$BASE" python -m scripts.bench.pii_score run --system shim \
    --corpus "$corpus" --out "$OUT/$name-shim-v030.jsonl"
  uv run --locked --with "$SPACY_MODEL" python -m scripts.bench.pii_score run --system presidio \
    --corpus "$corpus" --out "$OUT/$name-presidio.jsonl"
  rm -f "$CAPTURES"/*.jsonl
  MOCK_RECORD=/captures/upstream.jsonl \
    PRESIDIO_ANALYZER_API_BASE=http://relay-analyzer:3000 \
    PRESIDIO_ANONYMIZER_API_BASE=http://relay-anonymizer:3000 \
    litellm_up relay-analyzer relay-anonymizer
  py scripts.bench.pii_score run --system litellm --corpus "$corpus" --captures "$CAPTURES" \
    --out "$OUT/$name-litellm.jsonl"
  down
}

for step in "${steps[@]}"; do
  case $step in
    corpus) py scripts.bench.pii_corpus --out "$OUT" | tee "$OUT/corpus.sha256" ;;
    detection) score "$OUT/corpus.jsonl" ;;
    evasion) score "$OUT/evasion.jsonl" ;;
    middleware)
      idle
      py scripts.bench_middleware --sizes 1 4 16 32 50 | tee -a "$OUT/middleware-main.txt"
      uv run --locked --project "$BASE" python -m scripts.bench_middleware --sizes 1 4 16 32 50 \
        | tee -a "$OUT/middleware-v030.txt"
      ;;
    overhead)
      "${COMPOSE[@]}" build shim-main presidio-analyzer presidio-anonymizer
      for group in "shim-main" "shim-main-noprivacy" "shim-v030"; do
        idle; up mock "$group"
        port=$("${COMPOSE[@]}" port "$group" 8000 | cut -d: -f2)
        wait_http "http://127.0.0.1:$port/health"
        py scripts.bench.overhead --targets mock "$group" --out "$OUT/overhead.jsonl"
        memory
        down
      done
      idle; litellm_up
      py scripts.bench.overhead --targets mock litellm litellm-presidio --out "$OUT/overhead.jsonl"
      memory
      down
      ;;
    savings)
      [[ -n $ENV_FILE ]] || { echo "--savings needs --env <file with the provider keys>" >&2; exit 2; }
      uv run --locked --extra images python -m scripts.bench.savings --env "$ENV_FILE" \
        --out "$OUT/savings.jsonl"
      ;;
    report)
      {
        py scripts.bench.pii_score report --corpus "$OUT/corpus.jsonl" --evasion "$OUT/evasion.jsonl" \
          "$OUT"/corpus-*.jsonl "$OUT"/evasion-*.jsonl
        echo; py scripts.bench.overhead --report "$OUT/overhead.jsonl"
        echo; py scripts.bench.savings --report "$OUT/savings.jsonl"
      } | tee "$OUT/report.md"
      ;;
    *) echo "unknown step $step" >&2; exit 2 ;;
  esac
done
