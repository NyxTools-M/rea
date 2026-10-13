import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import {
  classifyElectronIpcPairings as classifyPairings,
  unambiguousElectronIpcPairings as uniquePairings,
  isRendererTransmission,
  isMainHandler,
} from "../../domain/javascript/electronCallPathJoins.js";
import type { ElectronIpcFinding } from "../../domain/javascript/electronStaticAnalysisTypes.js";
import type { ElectronBoundarySummary } from "../../domain/javascript/javascriptApplicationAnalysis.js";
import type { JavaScriptModuleArtifactAnalysis } from "./JavaScriptArtifactAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { resolveArtifactPathByContext } from "./JavaScriptArtifactPathResolution.js";

/** One IPC fact retaining its exact owning artifact for graph projection. */
export interface ElectronIpcRecord {
  readonly key: string;
  readonly file: JavaScriptArtifactFile;
  readonly finding: ElectronIpcFinding;
}

/** An unambiguous literal renderer-to-main static pairing. */
export interface ElectronIpcPairing {
  readonly transmission: ElectronIpcRecord;
  readonly handler: ElectronIpcRecord;
}

/** Pairing state for one renderer transmission without overclaiming ambiguity. */
export interface ElectronIpcPairingState {
  readonly transmission: ElectronIpcRecord;
  readonly candidates: readonly ElectronIpcRecord[];
  readonly status: "paired" | "ambiguous" | "unpaired";
}

/** Flatten all per-file IPC facts into deterministic application records. */
export const collectElectronIpcRecords = (
  analysis: JavaScriptModuleArtifactAnalysis,
): readonly ElectronIpcRecord[] =>
  analysis.files
    .flatMap(({ file, javascript }) =>
      (javascript?.electron.ipc ?? []).map((finding) => ({
        key: ipcRecordKey(file.path, finding),
        file,
        finding,
      })),
    )
    .sort((left, right) => compareUnicodeCodePoints(left.key, right.key));

/** Shared domain pairing semantics also drive parent resource admission. */
export const classifyElectronIpcPairings = (
  records: readonly ElectronIpcRecord[],
): readonly ElectronIpcPairingState[] => classifyPairings(records);
export const unambiguousElectronIpcPairings = (
  records: readonly ElectronIpcRecord[],
): readonly ElectronIpcPairing[] => uniquePairings(records);

/** Summarize static Electron findings without treating gaps as absence. */
export const summarizeElectronBoundaries = (
  analysis: JavaScriptModuleArtifactAnalysis,
): ElectronBoundarySummary => {
  const files = new Map(analysis.files.map(({ file }) => [file.path, file]));
  const javascript = analysis.files.flatMap(({ javascript: value }) =>
    value === null ? [] : [value],
  );
  const windows = javascript.flatMap(
    ({ electron }) => electron.browser_windows,
  );
  const bridges = javascript.flatMap(
    ({ electron }) => electron.context_bridge_apis,
  );
  const validations = javascript.flatMap(
    ({ electron }) => electron.sender_validations,
  );
  const utilities = analysis.files.flatMap(({ file, javascript: value }) =>
    (value?.electron.utility_processes ?? []).map((finding) => ({
      file,
      finding,
    })),
  );
  const nativeBindings = analysis.files.flatMap(({ file, javascript: value }) =>
    (value?.electron.native_addon_bindings ?? []).map((finding) => ({
      file,
      finding,
    })),
  );
  const ipc = collectElectronIpcRecords(analysis);
  const pairing = classifyElectronIpcPairings(ipc);
  const literalChannels = new Set(
    ipc.flatMap(({ finding }) =>
      finding.channel === null ? [] : [finding.channel],
    ),
  );
  return {
    browser_windows: windows.length,
    explicit_web_preferences: windows.reduce(
      (count, window) => count + window.web_preferences.length,
      0,
    ),
    preload_entrypoints: windows.filter(
      ({ preload_path: path }) => path !== null,
    ).length,
    context_bridge_apis: bridges.length,
    exposed_api_members: bridges.reduce(
      (count, bridge) => count + bridge.members.length,
      0,
    ),
    ipc: {
      operations: ipc.length,
      literal_channels: literalChannels.size,
      dynamic_channel_operations: ipc.filter(
        ({ finding }) => finding.channel === null,
      ).length,
      renderer_transmissions: ipc.filter(isRendererTransmission).length,
      renderer_listeners: ipc.filter(
        ({ finding }) =>
          finding.side === "renderer" && finding.mode === "listen",
      ).length,
      main_handlers: ipc.filter(isMainHandler).length,
      paired_renderer_transmissions: pairing.filter(
        ({ status }) => status === "paired",
      ).length,
      ambiguous_renderer_transmissions: pairing.filter(
        ({ status }) => status === "ambiguous",
      ).length,
      unpaired_literal_renderer_transmissions: pairing.filter(
        ({ status, transmission }) =>
          status === "unpaired" && transmission.finding.channel !== null,
      ).length,
    },
    sender_validation_observations: validations.length,
    utility_processes: utilities.length,
    resolved_utility_entrypoints: utilities.filter(
      ({ file, finding }) =>
        finding.module_path !== null &&
        resolvesToFile({
          file,
          specifier: finding.module_path,
          context: finding.module_resolution_context,
          files,
        }),
    ).length,
    native_addon_bindings: nativeBindings.length,
    resolved_native_addon_bindings: nativeBindings.filter(({ file, finding }) =>
      resolvesToFile({
        file,
        specifier: finding.specifier,
        context: "module-specifier",
        files,
        kind: "native-addon",
        moduleKind: finding.module_kind,
      }),
    ).length,
  };
};

interface ResolveToFileInput {
  readonly file: JavaScriptArtifactFile;
  readonly specifier: string;
  readonly context: "module-specifier" | "filesystem-expression";
  readonly files: ReadonlyMap<string, JavaScriptArtifactFile>;
  readonly kind?: JavaScriptArtifactFile["kind"];
  readonly moduleKind?: "import" | "require";
}

const resolvesToFile = (input: ResolveToFileInput): boolean => {
  const resolved = resolveArtifactPathByContext({
    declaredPath: input.specifier,
    sourcePath: input.file.path,
    context: input.context,
    files: input.files,
    ...(input.moduleKind === undefined ? {} : { moduleKind: input.moduleKind }),
  }).resolved_path;
  return (
    resolved !== null &&
    (input.kind === undefined || input.files.get(resolved)?.kind === input.kind)
  );
};

const ipcRecordKey = (path: string, finding: ElectronIpcFinding): string => {
  const identity = `${path}\0${String(finding.location.start.line)}:${String(finding.location.start.column)}\0${finding.side}\0${finding.operation}\0${finding.channel ?? finding.channel_expression}\0${JSON.stringify(finding.handler_location)}`;
  return finding.invocation_location === undefined
    ? identity
    : `${identity}\0${String(finding.invocation_location.start.line)}:${String(finding.invocation_location.start.column)}`;
};
