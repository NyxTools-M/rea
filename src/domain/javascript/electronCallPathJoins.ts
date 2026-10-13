import type {
  ElectronCallPath,
  ElectronIpcFinding,
} from "./electronStaticAnalysisTypes.js";
import type {
  JavaScriptSourceRange,
  JavaScriptStaticAnalysis,
} from "./javascriptStaticAnalysisTypes.js";

interface IpcRecord {
  readonly finding: ElectronIpcFinding;
}
export const isRendererTransmission = ({ finding }: IpcRecord): boolean =>
  finding.side === "renderer" &&
  (finding.mode === "send" || finding.mode === "invoke");
export const isMainHandler = ({ finding }: IpcRecord): boolean =>
  finding.side === "main" &&
  (finding.mode === "listen" || finding.mode === "handle");

/** One canonical literal-channel pairing owner for admission and projection. */
export const classifyElectronIpcPairings = <Record extends IpcRecord>(
  records: readonly Record[],
): readonly {
  readonly transmission: Record;
  readonly candidates: readonly Record[];
  readonly status: "paired" | "ambiguous" | "unpaired";
}[] => {
  const handlers = new Map<string, Record[]>();
  for (const record of records)
    if (isMainHandler(record) && record.finding.channel !== null) {
      const key = JSON.stringify([record.finding.channel, record.finding.mode]);
      const bucket = handlers.get(key) ?? [];
      bucket.push(record);
      handlers.set(key, bucket);
    }
  return records
    .filter(
      (r) =>
        isRendererTransmission(r) && r.finding.operation !== "send-to-host",
    )
    .map((transmission) => {
      const candidates =
        transmission.finding.channel === null
          ? []
          : (handlers.get(
              JSON.stringify([
                transmission.finding.channel,
                transmission.finding.mode === "invoke" ? "handle" : "listen",
              ]),
            ) ?? []);
      return {
        transmission,
        candidates,
        status:
          candidates.length === 1
            ? "paired"
            : candidates.length > 1
              ? "ambiguous"
              : "unpaired",
      };
    });
};
export const unambiguousElectronIpcPairings = <Record extends IpcRecord>(
  records: readonly Record[],
): readonly { readonly transmission: Record; readonly handler: Record }[] =>
  classifyElectronIpcPairings(records).flatMap((state) =>
    state.status === "paired" && state.candidates[0] !== undefined
      ? [{ transmission: state.transmission, handler: state.candidates[0] }]
      : [],
  );

const rangeKey = (range: JavaScriptSourceRange): string =>
  `${String(range.start.line)}:${String(range.start.column)}:${String(range.end.line)}:${String(range.end.column)}`;

/** Exact terminal/IPC and optional invocation matching, shared with the graph. */
export const electronCallPathMatchesIpc = (
  sourcePath: string,
  path: ElectronCallPath,
  record: {
    readonly file: { readonly path: string };
    readonly finding: ElectronIpcFinding;
  },
): boolean => {
  const finding = record.finding;
  const invocation = finding.invocation_location;
  const kind =
    finding.mode === "send" || finding.mode === "invoke" ? "terminal" : "ipc";
  return (
    sourcePath === record.file.path &&
    path.channel === finding.channel &&
    path.steps.some(
      (step) =>
        step.kind === kind &&
        rangeKey(step.location) === rangeKey(finding.location),
    ) &&
    (invocation === undefined ||
      path.steps.some(
        (step) =>
          (step.kind === "call" || step.kind === "exposure") &&
          rangeKey(step.location) === rangeKey(invocation),
      ))
  );
};

export interface ElectronJoinSummary {
  readonly file: { readonly path: string };
  readonly finding: ElectronIpcFinding;
  readonly paths: number;
  readonly conditionsBytes: number;
}

/** Compact counters, not an allocated Cartesian edge array. */
export const summarizeElectronCallPathJoins = (
  facts: JavaScriptStaticAnalysis,
  sourcePath: string,
): readonly ElectronJoinSummary[] => {
  const index = new Map<string, Set<ElectronCallPath>>();
  for (const path of facts.electron.call_paths ?? []) {
    const kind =
      path.entry_kind === "bridge-member"
        ? "terminal"
        : path.entry_kind === "ipc-handler"
          ? "ipc"
          : null;
    if (kind === null) continue;
    for (const step of path.steps)
      if (step.kind === kind) {
        const key = JSON.stringify([
          path.entry_kind,
          path.channel,
          rangeKey(step.location),
        ]);
        const bucket = index.get(key) ?? new Set<ElectronCallPath>();
        bucket.add(path);
        index.set(key, bucket);
      }
  }
  return facts.electron.ipc.map((finding) => {
    const record = { file: { path: sourcePath }, finding };
    const entry = finding.side === "renderer" ? "bridge-member" : "ipc-handler";
    const candidates =
      index.get(
        JSON.stringify([entry, finding.channel, rangeKey(finding.location)]),
      ) ?? [];
    let paths = 0,
      conditionsBytes = 0;
    for (const path of candidates)
      if (electronCallPathMatchesIpc(sourcePath, path, record)) {
        paths++;
        conditionsBytes += Buffer.byteLength(JSON.stringify(path.conditions));
      }
    return { ...record, paths, conditionsBytes };
  });
};

/** Retained schema/identity/evidence/serialization copies, at the existing 8x
 * projection factor. Includes cross-file pairings and repeated handler guards. */
export const estimateElectronCallPathJoinProjection = (
  records: readonly ElectronJoinSummary[],
): number => {
  let bytes = 0;
  for (const { transmission, handler } of unambiguousElectronIpcPairings(
    records,
  )) {
    const metadata =
      2048 +
      4 * Buffer.byteLength(transmission.file.path) +
      4 * Buffer.byteLength(handler.file.path) +
      2 * Buffer.byteLength(transmission.finding.channel ?? "");
    bytes +=
      transmission.paths *
      (handler.paths * metadata + 2 * handler.conditionsBytes) *
      8;
  }
  return bytes;
};
