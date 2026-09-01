#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_GRANT_SECRET='test-egress-grant-secret-at-least-32-bytes'
TEST_INTERNAL_TOKEN='test-internal-service-token-at-least-32-bytes'
TEST_REDIS_PASSWORD='test only:$redis#password&--flag'
SHIPPED_GRANT_SECRET='localdev-egress-grant-secret-change-me-32b'
SHIPPED_INTERNAL_TOKEN='localdev-internal-service-token'

for command in docker jq sort sed env; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing required command: $command" >&2
        exit 1
    fi
done

compose_version="$(docker compose version --short | sed -E 's/^v//; s/[+-].*$//')"
minimum_version='2.20.0'
if [[ "$(printf '%s\n%s\n' "$minimum_version" "$compose_version" | sort -V | sed -n '1p')" != "$minimum_version" ]]; then
    echo "docker compose $minimum_version or newer is required for include; found $compose_version" >&2
    exit 1
fi

render_gateway() {
    local compose_file="$1"
    local grant_secret="${2:-$TEST_GRANT_SECRET}"
    local internal_token="${3:-$TEST_INTERNAL_TOKEN}"
    CODEAPI_EGRESS_GRANT_SECRET="$grant_secret" \
    CODEAPI_INTERNAL_SERVICE_TOKEN="$internal_token" \
    REDIS_PASSWORD="$TEST_REDIS_PASSWORD" \
    CODEAPI_HARDENED_SANDBOX_MODE=false \
    CODEAPI_EGRESS_LEDGER_REQUIRED=false \
        docker compose -f "$compose_file" config --format json
}

auth_values_are_deployable() {
    local rendered="$1"
    local service="${2:-egress_gateway}"
    jq -e \
        --arg service "$service" \
        --arg shipped_grant "$SHIPPED_GRANT_SECRET" \
        --arg shipped_internal "$SHIPPED_INTERNAL_TOKEN" '
        (.services[$service].environment.CODEAPI_EGRESS_GRANT_SECRET | type == "string" and length >= 32)
        and (.services[$service].environment.CODEAPI_INTERNAL_SERVICE_TOKEN | type == "string" and length >= 32)
        and .services[$service].environment.CODEAPI_EGRESS_GRANT_SECRET != $shipped_grant
        and .services[$service].environment.CODEAPI_INTERNAL_SERVICE_TOKEN != $shipped_internal
    ' <<<"$rendered" >/dev/null
}

canonical="$(render_gateway "$ROOT/docker-compose.yaml")"
w799="$(render_gateway "$ROOT/docker-compose.w799-egress.yml")"
external_fixture="$(
    CODEAPI_EGRESS_GRANT_SECRET="$TEST_GRANT_SECRET" \
    CODEAPI_INTERNAL_SERVICE_TOKEN="$TEST_INTERNAL_TOKEN" \
        docker compose -f "$ROOT/docker-compose.external-fetch-test.yml" config --format json
)"

if ! jq -e --arg redis_password "$TEST_REDIS_PASSWORD" '
    . as $root
    | .services.egress_gateway.environment.CODEAPI_HARDENED_SANDBOX_MODE == "true"
      and .services.egress_gateway.environment.CODEAPI_EGRESS_LEDGER_REQUIRED == "true"
      and .services.egress_gateway.environment.REDIS_HOST == "redis"
      and all(["api", "service-worker", "egress_gateway", "tool_call_server", "file_server"][];
        . as $service
        | $root.services[$service].environment.REDIS_PASSWORD == $redis_password)
      and $root.services.redis.command == ["redis-server", "--requirepass", $redis_password]
' <<<"$canonical" >/dev/null; then
    echo "docker-compose.yaml: hardened gateway or shared Redis credential wiring is incomplete" >&2
    exit 1
fi

if ! auth_values_are_deployable "$canonical"; then
    echo "docker-compose.yaml rendered a shipped local gateway credential" >&2
    exit 1
fi
if ! auth_values_are_deployable "$external_fixture" 'egress-gateway'; then
    echo "docker-compose.external-fetch-test.yml rendered a shipped local gateway credential" >&2
    exit 1
fi
if ! jq -e '
    . as $root
    | .services["egress-gateway"].environment.CODEAPI_INTERNAL_SERVICE_TOKEN as $internal
    | .services["egress-gateway"].environment.CODEAPI_EGRESS_GRANT_SECRET as $grant
    | all(["file-server", "tool-call-server", "service-worker", "api", "e2e"][];
        . as $service
        | $root.services[$service].environment.CODEAPI_INTERNAL_SERVICE_TOKEN == $internal)
      and .services.e2e.environment.CODEAPI_EGRESS_GRANT_SECRET == $grant
' <<<"$external_fixture" >/dev/null; then
    echo "docker-compose.external-fetch-test.yml gateway credentials are inconsistent across services" >&2
    exit 1
fi
if auth_values_are_deployable "$(render_gateway "$ROOT/docker-compose.yaml" "$SHIPPED_GRANT_SECRET")"; then
    echo "gateway compose preflight must reject the shipped local grant secret" >&2
    exit 1
fi
if auth_values_are_deployable "$(render_gateway "$ROOT/docker-compose.yaml" "$TEST_GRANT_SECRET" "$SHIPPED_INTERNAL_TOKEN")"; then
    echo "gateway compose preflight must reject the shipped local internal token" >&2
    exit 1
fi

if [[ "$(jq -S . <<<"$canonical")" != "$(jq -S . <<<"$w799")" ]]; then
    echo "docker-compose.w799-egress.yml must render exactly the canonical compose model" >&2
    exit 1
fi

wrapper_model="$(sed -E '/^[[:space:]]*(#|$)/d' "$ROOT/docker-compose.w799-egress.yml")"
if [[ "$wrapper_model" != $'include:\n  - docker-compose.yaml' ]]; then
    echo "docker-compose.w799-egress.yml must only include docker-compose.yaml" >&2
    exit 1
fi

for compose_file in docker-compose.yaml docker-compose.w799-egress.yml; do
    if env -u REDIS_PASSWORD \
        CODEAPI_EGRESS_GRANT_SECRET="$TEST_GRANT_SECRET" \
        CODEAPI_INTERNAL_SERVICE_TOKEN="$TEST_INTERNAL_TOKEN" \
        docker compose --env-file /dev/null -f "$ROOT/$compose_file" config >/dev/null 2>&1; then
        echo "$compose_file must require REDIS_PASSWORD when it is unset" >&2
        exit 1
    fi
    if REDIS_PASSWORD='' \
        CODEAPI_EGRESS_GRANT_SECRET="$TEST_GRANT_SECRET" \
        CODEAPI_INTERNAL_SERVICE_TOKEN="$TEST_INTERNAL_TOKEN" \
        docker compose --env-file /dev/null -f "$ROOT/$compose_file" config >/dev/null 2>&1; then
        echo "$compose_file must require REDIS_PASSWORD when it is blank" >&2
        exit 1
    fi
done

if env -u CODEAPI_EGRESS_GRANT_SECRET \
    CODEAPI_INTERNAL_SERVICE_TOKEN="$TEST_INTERNAL_TOKEN" \
    REDIS_PASSWORD="$TEST_REDIS_PASSWORD" \
    docker compose -f "$ROOT/docker-compose.yaml" config >/dev/null 2>&1; then
    echo "docker-compose.yaml must require CODEAPI_EGRESS_GRANT_SECRET independently" >&2
    exit 1
fi
if env -u CODEAPI_INTERNAL_SERVICE_TOKEN \
    CODEAPI_EGRESS_GRANT_SECRET="$TEST_GRANT_SECRET" \
    REDIS_PASSWORD="$TEST_REDIS_PASSWORD" \
    docker compose -f "$ROOT/docker-compose.yaml" config >/dev/null 2>&1; then
    echo "docker-compose.yaml must require CODEAPI_INTERNAL_SERVICE_TOKEN independently" >&2
    exit 1
fi

for compose_file in docker-compose.local-dev.yml docker-compose.scalable.yml; do
    if env -u CODEAPI_INTERNAL_SERVICE_TOKEN \
        docker compose -f "$ROOT/$compose_file" config >/dev/null 2>&1; then
        echo "$compose_file must require CODEAPI_INTERNAL_SERVICE_TOKEN" >&2
        exit 1
    fi
done
