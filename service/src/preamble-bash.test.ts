import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, test } from 'bun:test';
import { extractPendingFromStdout, type LCTool } from './preamble';
import { generateBashReplayPostamble, generateBashReplayPreamble } from './preamble-bash';

interface BashRunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  signal?: string;
}

interface BashRunOptions {
  history?: Record<string, unknown>;
  timeoutMs?: number;
  bashEnv?: string;
  env?: Record<string, string>;
}

const executionId = 'exec_bash_unit';
const tools: LCTool[] = [
  {
    name: 'get_weather',
    description: 'Get weather for a city.',
    parameters: {
      type: 'object',
      properties: { city: { type: 'string' } },
      required: ['city'],
    },
  },
  {
    name: 'calculate',
    description: 'Evaluate an expression.',
    parameters: {
      type: 'object',
      properties: { expression: { type: 'string' } },
      required: ['expression'],
    },
  },
];
const clickHouseTool: LCTool = {
  name: 'run_select_query_mcp_ClickHouse',
  description: 'Run a ClickHouse SELECT query.',
  parameters: {
    type: 'object',
    properties: {
      serviceId: { type: 'string' },
      query: { type: 'string' },
    },
    required: ['serviceId', 'query'],
  },
};

function assemble(userCode: string, toolSet: LCTool[] = tools): string {
  return [
    generateBashReplayPreamble({ executionId, tools: toolSet }),
    userCode,
    generateBashReplayPostamble(),
  ].join('\n');
}

function runBash(script: string, options: number | BashRunOptions = {}): BashRunResult {
  const timeoutMs = typeof options === 'number' ? options : options.timeoutMs ?? 3000;
  const history = typeof options === 'number' ? {} : options.history ?? {};
  const bashEnv = typeof options === 'number' ? undefined : options.bashEnv;
  const dir = mkdtempSync(join(tmpdir(), 'ptc-bash-unit-'));
  const file = join(dir, 'main.sh');
  const historyPath = join(dir, 'history.json');
  writeFileSync(file, script, { mode: 0o755 });
  writeFileSync(historyPath, JSON.stringify(history));
  const bashEnvPath = join(dir, 'original-env.sh');
  if (bashEnv != null) {
    writeFileSync(bashEnvPath, bashEnv);
  }
  try {
    const stdout = execFileSync('bash', [file], {
      env: {
        ...process.env,
        ...(typeof options === 'number' ? undefined : options.env),
        PTC_HISTORY_PATH: historyPath,
        ...(bashEnv != null ? { BASH_ENV: bashEnvPath } : {}),
      },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs,
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (err: unknown) {
    const e = err as {
      stdout?: Buffer | string;
      stderr?: Buffer | string;
      status?: number;
      signal?: string;
    };
    return {
      stdout: e.stdout ? String(e.stdout) : '',
      stderr: e.stderr ? String(e.stderr) : '',
      exitCode: e.status ?? 1,
      signal: e.signal,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function pendingNames(stdout: string): string[] {
  const parsed = extractPendingFromStdout(stdout, executionId);
  return (parsed.pending ?? []).map(call => call.tool_name).sort();
}

describe('generateBashReplayPreamble - command substitution pending emission', () => {
  test('replays dependent tool calls from a generated child Bash script under errexit', () => {
    const userCode = `
cat > "\${0%/*}/child.sh" <<'CHILD'
first=$(calculate '{"expression":"2+3"}')
second=$(calculate "{\\"expression\\":\\"$first+1\\"}")
printf 'CHILD_RESULT=%s\\n' "$second"
CHILD
bash -e "\${0%/*}/child.sh"
echo "PARENT_DONE"
`;
    const firstRun = runBash(assemble(userCode), { bashEnv: 'set -e' });
    const first = extractPendingFromStdout(firstRun.stdout, executionId);
    expect(first.pending?.map(call => call.input)).toEqual([{ expression: '2+3' }]);
    expect(first.stdout).not.toContain('CHILD_RESULT');
    expect(first.stdout).not.toContain('PARENT_DONE');
    const history: Record<string, unknown> = {};
    const firstCall = first.pending![0];
    history[firstCall.call_id] = {
      result: 5,
      tool_name: firstCall.tool_name,
      input_hash: firstCall.input_hash,
      call_site: firstCall.call_site,
    };
    const secondRun = runBash(assemble(userCode), { history, bashEnv: 'set -e' });
    const second = extractPendingFromStdout(secondRun.stdout, executionId);
    expect(second.pending?.map(call => call.input)).toEqual([{ expression: '5+1' }]);
    expect(second.stdout).not.toContain('CHILD_RESULT');
    const secondCall = second.pending![0];
    history[secondCall.call_id] = {
      result: 6,
      tool_name: secondCall.tool_name,
      input_hash: secondCall.input_hash,
      call_site: secondCall.call_site,
    };
    const completedRun = runBash(assemble(userCode), { history, bashEnv: 'set -e' });
    const completed = extractPendingFromStdout(completedRun.stdout, executionId);
    expect(completedRun.exitCode).toBe(0);
    expect(completed.pending).toBeNull();
    expect(completed.stdout).toContain('CHILD_RESULT=6');
    expect(completed.stdout).toContain('PARENT_DONE');
  });

  test('emits one parent sentinel for parallel calls in a captured child shell', () => {
    const userCode = `
cat > "\${0%/*}/child-parallel.sh" <<'CHILD'
get_weather '{"city":"Oslo"}' &
calculate '{"expression":"2+3"}' &
wait
echo CHILD_DONE
CHILD
captured=$(bash "\${0%/*}/child-parallel.sh")
printf 'CAPTURED=%s\\n' "$captured"
`;
    const firstRun = runBash(assemble(userCode));
    const first = extractPendingFromStdout(firstRun.stdout, executionId);
    expect(pendingNames(firstRun.stdout)).toEqual(['calculate', 'get_weather']);
    expect(first.stdout).not.toContain('CHILD_DONE');
    expect(first.stdout).not.toContain('CAPTURED=');
    const history = Object.fromEntries(first.pending!.map(call => [
      call.call_id,
      {
        result: call.tool_name === 'calculate' ? 5 : { temperature: 13 },
        tool_name: call.tool_name,
        input_hash: call.input_hash,
        call_site: call.call_site,
      },
    ]));
    const completedRun = runBash(assemble(userCode), { history });
    const completed = extractPendingFromStdout(completedRun.stdout, executionId);
    expect(completedRun.exitCode).toBe(0);
    expect(completed.pending).toBeNull();
    expect(completed.stdout).toContain('CHILD_DONE');
    expect(completed.stdout).toContain('"temperature":13');
    expect(completed.stdout).toContain('CAPTURED=');
  });

  test('propagates a cached child tool error under explicit errexit', () => {
    const userCode = `
bash -e -c 'result=$(get_weather "{}"); echo CHILD_AFTER_ERROR'
echo PARENT_AFTER_ERROR
`;
    const first = extractPendingFromStdout(runBash(assemble(userCode)).stdout, executionId);
    const call = first.pending![0];
    const run = runBash(assemble(userCode), {
      history: {
        [call.call_id]: {
          is_error: true,
          error_message: 'station unavailable',
          tool_name: call.tool_name,
          input_hash: call.input_hash,
          call_site: call.call_site,
        },
      },
      bashEnv: 'set -e',
    });
    expect(run.exitCode).toBe(1);
    expect(run.stderr.match(/station unavailable/g)).toHaveLength(1);
    expect(run.stdout).not.toContain('CHILD_AFTER_ERROR');
    expect(run.stdout).not.toContain('PARENT_AFTER_ERROR');
    expect(extractPendingFromStdout(run.stdout, executionId).pending).toBeNull();
  });

  test('lets a child Bash -e script catch a cached tool error and continue', () => {
    const userCode = `
cat > "\${0%/*}/child-catchable.sh" <<'CHILD'
first=$(calculate '{"expression":"2+3"}')
printf 'FIRST=%s\\n' "$first"
set +e
second=$(get_weather '{"city":"Paris"}' 2> "\${0%/*}/child-error.txt")
status=$?
set -e
printf 'SECOND_STATUS=%s\\n' "$status"
printf 'SECOND_ERR=%s\\n' "$(cat "\${0%/*}/child-error.txt")"
printf 'CHILD_DONE\\n'
CHILD
bash -e "\${0%/*}/child-catchable.sh"
printf 'PARENT_DONE\\n'
`;
    const firstRun = runBash(assemble(userCode));
    const first = extractPendingFromStdout(firstRun.stdout, executionId);
    expect(firstRun.exitCode).toBe(0);
    expect(first.pending).toHaveLength(1);
    expect(first.pending?.[0]?.tool_name).toBe('calculate');

    const firstCall = first.pending![0];
    const history: Record<string, unknown> = {
      [firstCall.call_id]: {
        result: 5,
        tool_name: firstCall.tool_name,
        input_hash: firstCall.input_hash,
        call_site: firstCall.call_site,
      },
    };
    const secondRun = runBash(assemble(userCode), { history });
    const second = extractPendingFromStdout(secondRun.stdout, executionId);
    expect(secondRun.exitCode).toBe(0);
    expect(second.stdout).toContain('FIRST=5');
    expect(second.pending).toHaveLength(1);
    expect(second.pending?.[0]?.tool_name).toBe('get_weather');

    const secondCall = second.pending![0];
    history[secondCall.call_id] = {
      is_error: true,
      error_message: 'station unavailable',
      tool_name: secondCall.tool_name,
      input_hash: secondCall.input_hash,
      call_site: secondCall.call_site,
    };
    const completedRun = runBash(assemble(userCode), { history });
    const completed = extractPendingFromStdout(completedRun.stdout, executionId);
    expect(completedRun.exitCode).toBe(0);
    expect(completed.pending).toBeNull();
    expect(completed.stdout).toContain('FIRST=5');
    expect(completed.stdout).toContain('SECOND_STATUS=1');
    expect(completed.stdout).toContain('SECOND_ERR=station unavailable');
    expect(completed.stdout.match(/station unavailable/g)).toHaveLength(1);
    expect(completed.stdout).toContain('CHILD_DONE');
    expect(completed.stdout).toContain('PARENT_DONE');
    expect(completedRun.stderr).not.toContain('station unavailable');
  });

  test('preserves the original Bash startup environment and ordinary child exit status', () => {
    const run = runBash(assemble(`
bash -c 'printf "ENV_COUNT=%s\\n" "$ENV_COUNT"; exit 7'
`), {
      bashEnv: 'export ENV_COUNT=$((${ENV_COUNT:-0} + 1))',
      env: { ENV_COUNT: '0' },
    });
    expect(run.stdout).toContain('ENV_COUNT=2');
    expect(run.exitCode).toBe(7);
    expect(extractPendingFromStdout(run.stdout, executionId).pending).toBeNull();
  });

  test('does not invoke tools that share bootstrap command names during initialization', () => {
    const run = runBash(assemble(
      `bash -c 'echo CHILD_DONE'`,
      ['cat', 'compgen', 'command'].map(name => ({
        name,
        description: 'A registered tool, not a shell initialization command.',
        parameters: { type: 'object', properties: {} },
      })),
    ));
    expect(run.exitCode).toBe(0);
    expect(run.stdout).toContain('CHILD_DONE');
    expect(extractPendingFromStdout(run.stdout, executionId).pending).toBeNull();
  });

  test('emits ClickHouse-style object input with SQL quotes from double-quoted JSON', () => {
    const run = runBash(assemble(`
SVC="45886e06-932b-4cff-bb49-3f7281d80717"
result=$(run_select_query_mcp_ClickHouse "{\\"serviceId\\":\\"$SVC\\",\\"query\\":\\"SELECT name, round(avg(tempAvg)/10.0, 2) AS avg_temp_c FROM system.columns WHERE database='default' AND table='uk_prices_3' AND tempAvg != -9999\\"}")
echo "AFTER: $result"
`, [clickHouseTool]));

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.tool_name).toBe('run_select_query_mcp_ClickHouse');
    expect(parsed.pending?.[0]?.input).toEqual({
      serviceId: '45886e06-932b-4cff-bb49-3f7281d80717',
      query:
        "SELECT name, round(avg(tempAvg)/10.0, 2) AS avg_temp_c FROM system.columns WHERE database='default' AND table='uk_prices_3' AND tempAvg != -9999",
    });
    expect(parsed.stdout).not.toContain('AFTER');
  });

  test('emits ClickHouse-style object input with shell-escaped SQL quotes', () => {
    const run = runBash(assemble(`
result=$(run_select_query_mcp_ClickHouse '{"serviceId":"45886e06-932b-4cff-bb49-3f7281d80717","query":"SELECT name, type FROM system.columns WHERE database='"'"'default'"'"' AND table='"'"'uk_prices_3'"'"' ORDER BY position"}')
echo "AFTER: $result"
`, [clickHouseTool]));

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.tool_name).toBe('run_select_query_mcp_ClickHouse');
    expect(parsed.pending?.[0]?.input).toEqual({
      serviceId: '45886e06-932b-4cff-bb49-3f7281d80717',
      query:
        "SELECT name, type FROM system.columns WHERE database='default' AND table='uk_prices_3' ORDER BY position",
    });
    expect(parsed.stdout).not.toContain('AFTER');
  });

  test('batches parallel ClickHouse-style command substitutions into one pending block', () => {
    const run = runBash(assemble(`
SVC="45886e06-932b-4cff-bb49-3f7281d80717"

{
  r1=$(run_select_query_mcp_ClickHouse "{\\"serviceId\\":\\"$SVC\\",\\"query\\":\\"SELECT name, type, comment FROM system.columns WHERE database='default' AND table='uk_prices_3' ORDER BY position\\"}")
  printf '%s\\n' "$r1" > /mnt/data/cols_uk.json
} &

{
  r2=$(run_select_query_mcp_ClickHouse "{\\"serviceId\\":\\"$SVC\\",\\"query\\":\\"SELECT name, type, comment FROM system.columns WHERE database='default' AND table='weather_noaa_mt' ORDER BY position\\"}")
  printf '%s\\n' "$r2" > /mnt/data/cols_weather.json
} &

{
  r3=$(run_select_query_mcp_ClickHouse "{\\"serviceId\\":\\"$SVC\\",\\"query\\":\\"SELECT name, engine, total_rows, formatReadableSize(total_bytes) AS size, sorting_key, partition_key FROM system.tables WHERE database='default' AND name IN ('uk_prices_3','weather_noaa_mt')\\"}")
  printf '%s\\n' "$r3" > /mnt/data/table_meta.json
} &

wait
echo "AFTER"
`, [clickHouseTool]), 3000);

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toHaveLength(3);
    expect(parsed.pending?.map(call => call.tool_name)).toEqual([
      'run_select_query_mcp_ClickHouse',
      'run_select_query_mcp_ClickHouse',
      'run_select_query_mcp_ClickHouse',
    ]);
    expect(parsed.pending?.map(call => (call.input as { query: string }).query).sort()).toEqual([
      "SELECT name, engine, total_rows, formatReadableSize(total_bytes) AS size, sorting_key, partition_key FROM system.tables WHERE database='default' AND name IN ('uk_prices_3','weather_noaa_mt')",
      "SELECT name, type, comment FROM system.columns WHERE database='default' AND table='uk_prices_3' ORDER BY position",
      "SELECT name, type, comment FROM system.columns WHERE database='default' AND table='weather_noaa_mt' ORDER BY position",
    ]);
    expect(parsed.stdout).not.toContain('AFTER');
  });

  test('emits a command-substitution tool call before later user code while another job is running', () => {
    const run = runBash(assemble(`
sleep 0.2 &
result=$(get_weather '{"city":"Madrid"}')
echo "AFTER: $result"
wait
`));

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.tool_name).toBe('get_weather');
    expect(parsed.pending?.[0]?.input).toEqual({ city: 'Madrid' });
    expect(parsed.stdout).not.toContain('AFTER');
  });

  test('batches background and command-substitution tool calls before command-substitution side effects', () => {
    const run = runBash(assemble(`
get_weather '{"city":"Oslo"}' &
result=$(calculate '{"expression":"2+3"}')
echo "SIDE_EFFECT: $result"
wait
`), 1500);

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(pendingNames(run.stdout)).toEqual(['calculate', 'get_weather']);
    expect(parsed.pending).toHaveLength(2);
    expect(parsed.stdout).not.toContain('SIDE_EFFECT');
  });

  test('waits for background compound commands that invoke tools later', () => {
    const run = runBash(assemble(`
(sleep 0.2; get_weather '{"city":"Paris"}') &
echo "AFTER LAUNCH"
`), 1500);

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.tool_name).toBe('get_weather');
    expect(parsed.pending?.[0]?.input).toEqual({ city: 'Paris' });
    expect(parsed.stdout).toContain('AFTER LAUNCH');
  });

  test('does not wait for unrelated background commands with tool names as arguments', () => {
    const run = runBash(assemble(`
bash -c 'sleep 2' get_weather &
echo "DONE"
`), 700);

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toBeNull();
    expect(parsed.stdout).toContain('DONE');
  });

  test('does not treat arithmetic expansion as command substitution while batching background tools', () => {
    const run = runBash(assemble(`
get_weather '{"city":"Oslo"}' &
sleep 0.1
x=$((1+1))
calculate '{"expression":"2+3"}' &
wait
echo "DONE $x"
`), 1500);

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(pendingNames(run.stdout)).toEqual(['calculate', 'get_weather']);
    expect(parsed.pending).toHaveLength(2);
    expect(parsed.stdout).not.toContain('DONE');
  });

  test('handles backtick command substitution without waiting for unrelated background jobs', () => {
    const run = runBash(assemble(`
sleep 5 &
result=\`get_weather '{"city":"Porto"}'\`
echo "AFTER: $result"
wait
`), 1500);

    const parsed = extractPendingFromStdout(run.stdout, executionId);
    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.tool_name).toBe('get_weather');
    expect(parsed.pending?.[0]?.input).toEqual({ city: 'Porto' });
    expect(parsed.stdout).not.toContain('AFTER');
  });

  test('replays parallel calls with identical signatures after call-site line numbers shift', () => {
    const userCode = `
for _ptc_i in 1 2; do
  get_weather '{"city":"Paris"}' &
done
wait
echo "DONE"
`;
    const firstRun = runBash(assemble(userCode));
    const firstParsed = extractPendingFromStdout(firstRun.stdout, executionId);
    expect(firstRun.exitCode).toBe(0);
    expect(firstParsed.pending).toHaveLength(2);

    const history = Object.fromEntries(
      firstParsed.pending!.map((call, index) => {
        expect(call.input_hash).toBeTruthy();
        expect(call.call_site).toBeTruthy();
        return [
          call.call_id,
          {
            result: { slot: index === 0 ? 'first' : 'second' },
            tool_name: call.tool_name,
            input_hash: call.input_hash,
            call_site: `${call.call_site}:old-preamble-offset`,
            received_at: index + 1,
          },
        ];
      }),
    );
    const replayRun = runBash(assemble(userCode), { history });
    const replayParsed = extractPendingFromStdout(replayRun.stdout, executionId);
    expect(replayRun.exitCode).toBe(0);
    expect(replayParsed.pending).toBeNull();
    expect(replayParsed.stdout).toContain('"slot":"first"');
    expect(replayParsed.stdout).toContain('"slot":"second"');
    expect(replayParsed.stdout).toContain('DONE');
  });

  test('replays identical signature matches in numeric call-id order', () => {
    const history = {
      call_1000: {
        result: { slot: 'thousand' },
        tool_name: 'get_weather',
        input: { city: 'Paris' },
        received_at: 1000,
      },
      call_999: {
        result: { slot: 'nine-nine-nine' },
        tool_name: 'get_weather',
        input: { city: 'Paris' },
        received_at: 999,
      },
    };

    const run = runBash(assemble(`
get_weather '{"city":"Paris"}'
printf '\\n'
get_weather '{"city":"Paris"}'
printf '\\nDONE\\n'
`), { history });
    const parsed = extractPendingFromStdout(run.stdout, executionId);

    expect(run.exitCode).toBe(0);
    expect(parsed.pending).toBeNull();
    expect(parsed.stdout.indexOf('"slot":"nine-nine-nine"')).toBeLessThan(
      parsed.stdout.indexOf('"slot":"thousand"'),
    );
    expect(parsed.stdout).toContain('DONE');
  });

  test('replays matching nonnumeric history keys without crashing counter parsing', () => {
    const history = {
      legacy_match: {
        result: { slot: 'legacy' },
        tool_name: 'get_weather',
        input: { city: 'Paris' },
        received_at: 1,
      },
    };

    const run = runBash(assemble(`
get_weather '{"city":"Paris"}'
printf '\\n'
calculate '{"expression":"2+3"}'
printf '\\nDONE\\n'
`), { history });
    const parsed = extractPendingFromStdout(run.stdout, executionId);

    expect(run.signal).not.toBe('SIGTERM');
    expect(run.exitCode).toBe(0);
    expect(parsed.stdout).toContain('"slot":"legacy"');
    expect(parsed.stdout).not.toContain('DONE');
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.call_id).toBe('call_001');
    expect(parsed.pending?.[0]?.tool_name).toBe('calculate');
  });

  test('skips stale numeric fallback entries after a nonnumeric signature match', () => {
    const history = {
      legacy_match: {
        result: { slot: 'legacy' },
        tool_name: 'get_weather',
        input: { city: 'Paris' },
        received_at: 1,
      },
      call_001: {
        result: { slot: 'stale' },
        tool_name: 'calculate',
        input: { expression: '9+9' },
        received_at: 2,
      },
    };

    const run = runBash(assemble(`
get_weather '{"city":"Paris"}'
printf '\\n'
calculate '{"expression":"2+3"}'
printf '\\nDONE\\n'
`), { history });
    const parsed = extractPendingFromStdout(run.stdout, executionId);

    expect(run.exitCode).toBe(0);
    expect(parsed.stdout).toContain('"slot":"legacy"');
    expect(parsed.stdout).not.toContain('"slot":"stale"');
    expect(parsed.stdout).not.toContain('DONE');
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.call_id).toBe('call_002');
    expect(parsed.pending?.[0]?.tool_name).toBe('calculate');
  });

  test('skips stale numeric fallback entries after a high numeric signature match', () => {
    const history = {
      call_010: {
        result: { slot: 'matched' },
        tool_name: 'get_weather',
        input: { city: 'Paris' },
        received_at: 10,
      },
      call_011: {
        result: { slot: 'stale' },
        tool_name: 'calculate',
        input: { expression: '9+9' },
        received_at: 11,
      },
    };

    const run = runBash(assemble(`
get_weather '{"city":"Paris"}'
printf '\\n'
calculate '{"expression":"2+3"}'
printf '\\nDONE\\n'
`), { history });
    const parsed = extractPendingFromStdout(run.stdout, executionId);

    expect(run.exitCode).toBe(0);
    expect(parsed.stdout).toContain('"slot":"matched"');
    expect(parsed.stdout).not.toContain('"slot":"stale"');
    expect(parsed.stdout).not.toContain('DONE');
    expect(parsed.pending).toHaveLength(1);
    expect(parsed.pending?.[0]?.call_id).toBe('call_012');
    expect(parsed.pending?.[0]?.tool_name).toBe('calculate');
  });
});
