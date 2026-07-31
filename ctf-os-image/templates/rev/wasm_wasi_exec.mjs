#!/usr/bin/node
/*
 * Minimal executable WASM/WASI boundary for the Rev runtime oracle.
 *
 * The Python parent validates and hash-binds the module before this process is
 * started.  This helper accepts no environment, filesystem, network, or
 * success-oracle controls from the challenge.  Stdin/stdout/stderr are the
 * inherited WASI descriptors and the only preopened tree is read-only
 * /challenge.
 */

import fs from "node:fs";
import process from "node:process";
import { WASI } from "node:wasi";

function fail(code) {
  process.stderr.write(`wasm_wasi_exec: ${code}\n`);
  process.exitCode = 125;
}

function parse(argv) {
  if (
    argv.length < 5 ||
    argv[0] !== "--module" ||
    argv[2] !== "--entry" ||
    argv[4] !== "--"
  ) {
    throw new Error("invalid_cli");
  }
  const modulePath = argv[1];
  const entrypoint = argv[3];
  if (
    !modulePath.startsWith("/challenge/") ||
    modulePath.includes("\0") ||
    !/^[A-Za-z_$][A-Za-z0-9_.$-]{0,255}$/.test(entrypoint)
  ) {
    throw new Error("invalid_cli");
  }
  return { modulePath, entrypoint, targetArgv: argv.slice(5) };
}

async function main() {
  const { modulePath, entrypoint, targetArgv } = parse(process.argv.slice(2));
  const wasi = new WASI({
    version: "preview1",
    args: [modulePath, ...targetArgv],
    env: {},
    preopens: { "/challenge": "/challenge" },
    returnOnExit: true,
  });
  const bytes = fs.readFileSync(modulePath);
  const module = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(module, {
    wasi_snapshot_preview1: wasi.wasiImport,
  });
  if (entrypoint === "_start") {
    const status = wasi.start(instance);
    process.exitCode = Number.isInteger(status) ? status & 0xff : 0;
    return;
  }
  if (typeof instance.exports[entrypoint] !== "function") {
    throw new Error("entrypoint_missing");
  }
  if (typeof instance.exports._initialize === "function") {
    wasi.initialize(instance);
  }
  const status = instance.exports[entrypoint]();
  if (
    status !== undefined &&
    (typeof status !== "number" || !Number.isInteger(status))
  ) {
    throw new Error("entrypoint_status_invalid");
  }
  process.exitCode = status === undefined ? 0 : status & 0xff;
}

try {
  await main();
} catch (error) {
  const code =
    error instanceof Error && /^[a-z0-9_]{1,64}$/.test(error.message)
      ? error.message
      : "runtime_failed";
  fail(code);
}
