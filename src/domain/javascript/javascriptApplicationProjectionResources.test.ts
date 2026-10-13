import { expect, it } from "vitest";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import { estimateJavaScriptStaticApplicationProjection } from "./javascriptApplicationProjectionResources.js";
import {
  estimateElectronCallPathJoinProjection,
  summarizeElectronCallPathJoins,
} from "./electronCallPathJoins.js";

it("counts cross-file joins regardless of checkpoint order and retains unique-handler semantics", () => {
  const preload = analyzeJavaScriptStaticSource(
    `const e=require("electron");const sender=channel=>(...args)=>e.ipcRenderer.send(channel,...args);e.contextBridge.exposeInMainWorld("desktop",{copy:sender("test:copy"),cut:sender("test:copy")});`,
  );
  const main = analyzeJavaScriptStaticSource(
    `const e=require("electron");e.ipcMain.addListener("test:copy",event=>{if(allowed(event)){event.sender.copy();event.sender.cut();}});`,
  );
  const sources = summarizeElectronCallPathJoins(preload, "preload.js");
  const handlers = summarizeElectronCallPathJoins(main, "main.js");
  expect(estimateElectronCallPathJoinProjection(sources)).toBe(0);
  expect(estimateElectronCallPathJoinProjection(handlers)).toBe(0);
  const joined = estimateElectronCallPathJoinProjection([
    ...sources,
    ...handlers,
  ]);
  expect(joined).toBeGreaterThanOrEqual(4 * 2048 * 8);
  expect(
    estimateElectronCallPathJoinProjection([...handlers, ...sources]),
  ).toBe(joined);
  expect(
    estimateElectronCallPathJoinProjection([
      ...sources,
      ...handlers,
      ...summarizeElectronCallPathJoins(main, "other-main.js"),
    ]),
  ).toBe(0);
});

const amplifiedSource = (count: number) => `const e=require("electron");
const sender=channel=>(...args)=>e.ipcRenderer.send(channel,...args);
e.contextBridge.exposeInMainWorld("desktop",{${Array.from({ length: count }, (_, i) => `copy${String(i)}:sender("test:copy")`).join(",")}});
e.ipcMain.addListener("test:copy",event=>{if(allowed(event)){${Array.from({ length: count }, (_, i) => `event.sender.copy${String(i)}();`).join("")}}});`;

it("forecasts Cartesian wrapper joins and their repeated guards before graph allocation", () => {
  const source = amplifiedSource(100);
  const facts = analyzeJavaScriptStaticSource(source);
  expect(facts.parse_error_count).toBe(0);
  const paths = facts.electron.call_paths ?? [];
  const sources = paths.filter((p) => p.entry_kind === "bridge-member").length;
  const targets = paths.filter((p) => p.entry_kind === "ipc-handler").length;
  expect(sources).toBe(100);
  expect(targets).toBe(100);
  const estimate = estimateJavaScriptStaticApplicationProjection(
    facts,
    Buffer.byteLength(JSON.stringify(facts)),
    "bundle.js",
  );
  expect(estimate).toBeGreaterThanOrEqual(sources * targets * 2048 * 8);
});
