/** @jsxImportSource react */
import * as Effect from "effect/Effect";
import { useEffect, useState, type JSX } from "react";
import {
  Box,
  ProgressBar,
  ProgressGroup,
  Spinner,
  Text,
  useTerminalSize,
} from "../CliKit/components.ts";
import { CliKit, theme } from "../CliKit/index.ts";
import { type EventSource, makeEventHub } from "./events.ts";

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type ScanEvent =
  | { kind: "start"; id: string }
  | { kind: "done"; id: string; count: number }
  | { kind: "error"; id: string; message: string };

export type DeleteEvent =
  | { kind: "pass"; pass: number }
  | { kind: "deleted"; id: string }
  | { kind: "failed"; id: string };

// ---------------------------------------------------------------------------
// Scan phase
// ---------------------------------------------------------------------------

interface ScanState {
  scanned: number;
  toDelete: number;
  inFlight: string[];
}

/**
 * A single left-to-right progress bar tracking scanned vs. outstanding
 * providers, with a running tally of resources to delete. While scanning, the
 * providers still in flight are listed below the bar so a slow/hanging
 * provider near the end is immediately identifiable. Per-provider detail is
 * printed to the console once scanning completes.
 */
function ScanProgress(props: {
  total: number;
  source: EventSource<ScanEvent>;
}): JSX.Element {
  const { total, source } = props;
  const { columns, rows } = useTerminalSize();
  const barWidth = Math.max(8, Math.min(32, columns - 30));
  const [state, setState] = useState<ScanState>(() => ({
    scanned: 0,
    toDelete: 0,
    inFlight: [],
  }));

  useEffect(() => {
    return source.subscribe((event) =>
      setState((prev) => {
        const inFlight = new Set(prev.inFlight);
        if (event.kind === "start") {
          inFlight.add(event.id);
          return { ...prev, inFlight: [...inFlight] };
        }
        inFlight.delete(event.id);
        return {
          scanned: prev.scanned + 1,
          toDelete: prev.toDelete + (event.kind === "done" ? event.count : 0),
          inFlight: [...inFlight],
        };
      }),
    );
  }, [source]);

  const done = state.scanned >= total;
  const stragglers = state.inFlight.slice(
    0,
    Math.max(1, Math.min(10, rows - 8)),
  );

  return (
    <Box flexDirection="column">
      <Box flexDirection="row">
        <ProgressBar
          value={total === 0 ? 1 : state.scanned / total}
          width={barWidth}
          variant={done ? "success" : "info"}
          showPercent={false}
        />
        <Text bold>
          {" "}
          {state.scanned}/{total}
        </Text>
        <Text tone="muted"> providers</Text>
        <Text tone="muted"> · </Text>
        <Text bold color={theme.color.warning}>
          {state.toDelete}
        </Text>
        <Text tone="muted"> to delete</Text>
      </Box>
      {!done && stragglers.length > 0 ? (
        <Box flexDirection="column">
          {stragglers.map((id) => (
            <Spinner key={id} label={<Text tone="muted">scanning {id}</Text>} />
          ))}
          {state.inFlight.length > stragglers.length ? (
            <Text tone="muted">
              {" "}
              …and {state.inFlight.length - stragglers.length} more
            </Text>
          ) : null}
        </Box>
      ) : null}
    </Box>
  );
}

export interface ScanUI {
  emit: (event: ScanEvent) => void;
  close: Effect.Effect<void>;
}

export const renderScan = Effect.fn(function* (total: number) {
  const cli = yield* CliKit;
  const hub = makeEventHub<ScanEvent>();
  const live = yield* cli.live.open(
    <ScanProgress total={total} source={hub.source} />,
  );
  return { emit: hub.emit, close: live.close } satisfies ScanUI;
});

// ---------------------------------------------------------------------------
// Delete phase
// ---------------------------------------------------------------------------

interface TypeProgress {
  total: number;
  deleted: number;
  failed: number;
}

function DeleteProgress(props: {
  totals: { id: string; total: number }[];
  source: EventSource<DeleteEvent>;
}): JSX.Element {
  const { totals, source } = props;
  const { columns } = useTerminalSize();
  const barWidth = Math.max(8, Math.min(32, columns - 30));
  const groupBarWidth = Math.max(6, Math.min(20, Math.floor(columns / 4)));
  const labelWidth = Math.max(12, Math.min(40, columns - groupBarWidth - 20));
  const grandTotal = totals.reduce((a, b) => a + b.total, 0);
  const [pass, setPass] = useState(1);
  const [rows, setRows] = useState<Map<string, TypeProgress>>(
    () =>
      new Map(
        totals.map((t) => [t.id, { total: t.total, deleted: 0, failed: 0 }]),
      ),
  );

  useEffect(() => {
    return source.subscribe((event) => {
      if (event.kind === "pass") {
        setPass(event.pass);
        // reset transient per-pass failure counters at the start of a pass
        setRows((prev) => {
          const next = new Map(prev);
          for (const [id, row] of next) next.set(id, { ...row, failed: 0 });
          return next;
        });
        return;
      }
      setRows((prev) => {
        const next = new Map(prev);
        const row = next.get(event.id);
        if (!row) return prev;
        if (event.kind === "deleted") {
          next.set(event.id, { ...row, deleted: row.deleted + 1 });
        } else {
          next.set(event.id, { ...row, failed: row.failed + 1 });
        }
        return next;
      });
    });
  }, [source]);

  const totalDeleted = [...rows.values()].reduce((a, b) => a + b.deleted, 0);
  const sorted = [...rows.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  return (
    <Box flexDirection="column">
      <Box flexDirection="row">
        <ProgressBar
          value={grandTotal === 0 ? 1 : totalDeleted / grandTotal}
          width={barWidth}
          variant="error"
          showPercent={false}
        />
        <Text bold>
          {" "}
          {totalDeleted}/{grandTotal}
        </Text>
        <Text tone="muted"> deleted</Text>
        <Text tone="muted"> · pass {pass}</Text>
      </Box>
      <ProgressGroup
        width={groupBarWidth}
        labelWidth={labelWidth}
        rows={sorted.map(([id, row]) => ({
          id,
          label: id,
          completed: row.deleted,
          total: row.total,
          failed: row.failed,
        }))}
      />
    </Box>
  );
}

export interface DeleteUI {
  emit: (event: DeleteEvent) => void;
  close: Effect.Effect<void>;
}

export const renderDelete = (
  totals: { id: string; total: number }[],
): Effect.Effect<DeleteUI> =>
  Effect.gen(function* () {
    const cli = yield* CliKit;
    const hub = makeEventHub<DeleteEvent>();
    const live = yield* cli.live.open(
      <DeleteProgress totals={totals} source={hub.source} />,
    );
    return { emit: hub.emit, close: live.close } satisfies DeleteUI;
  });
