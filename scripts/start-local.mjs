#!/usr/bin/env node
// Runs the whole system locally: API on :8000, web on :3000. Stop it with Ctrl+C.
//
//   node scripts/start-local.mjs            set up anything missing, then start
//   node scripts/start-local.mjs --reset    also delete the local database first
//
// No Docker needed: Redis is in-process, DeDi is the API's dev mock, and credentials are
// signed in-process. Everything runs on mock DISCOM data. Never use this for production.

import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import net from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const apiDir = join(root, "api");
const webDir = join(root, "web");
const isWindows = process.platform === "win32";
const venvPython = join(apiDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
const API_PORT = 8000; // part of the dev issuer DID, did:web:localhost%3A8000
const WEB_PORT = 3000; // the API's CORS setting and share links point here
const env = { ...process.env, CEP_ENVIRONMENT: "dev" };

function fail(message) {
  console.error(`\nCannot start: ${message}`);
  process.exit(1);
}

function step(message) {
  console.log(`> ${message}`);
}

function findPython() {
  const candidates = isWindows
    ? [["py", "-3.12"], ["py", "-3"], ["python"]]
    : [["python3.12"], ["python3"], ["python"]];
  for (const [command, ...args] of candidates) {
    const probe = spawnSync(command, [...args, "-c", "import sys; print(sys.version_info >= (3, 12))"], {
      encoding: "utf8",
    });
    if (probe.stdout?.trim() === "True") return [command, ...args];
  }
  fail("Python 3.12 or newer was not found.");
}

function setUpApi() {
  if (!existsSync(venvPython)) {
    step("Creating the Python environment");
    const [command, ...args] = findPython();
    execFileSync(command, [...args, "-m", "venv", join(apiDir, ".venv")], { stdio: "inherit" });
  }
  const ready = spawnSync(venvPython, ["-c", "import fastapi, ies_adapter, pyld, alembic"], { cwd: apiDir });
  if (ready.status !== 0) {
    step("Installing API dependencies (first run takes a few minutes)");
    execFileSync(venvPython, ["-m", "pip", "install", "-q", "-e", "../adapter", "-e", ".[dev]"], {
      cwd: apiDir,
      stdio: "inherit",
    });
  }
}

function setUpWeb() {
  if (existsSync(join(webDir, "node_modules", "next"))) return;
  step("Installing web dependencies (first run takes a few minutes)");
  const install = spawnSync("npm", ["ci"], { cwd: webDir, stdio: "inherit", shell: isWindows });
  if (install.status !== 0) fail("npm ci failed.");
}

function assertPortFree(port) {
  return new Promise((done) => {
    const socket = net.connect({ port, host: "127.0.0.1" });
    socket.once("connect", () => {
      socket.destroy();
      fail(`port ${port} is already in use. Stop whatever is using it and try again.`);
    });
    socket.once("error", () => done());
  });
}

const children = [];
let stopping = false;

function stopAll(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  console.log("\nStopping...");
  for (const child of children) {
    if (child.exitCode !== null) continue;
    // next dev starts its own workers, so the whole process tree has to go.
    if (isWindows) spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGTERM");
  }
  process.exit(exitCode);
}

function start(name, command, args, cwd) {
  const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  const prefix = (chunk) => {
    for (const line of chunk.toString().split(/\r?\n/)) {
      if (line.trim()) console.log(`[${name}] ${line}`);
    }
  };
  child.stdout.on("data", prefix);
  child.stderr.on("data", prefix);
  child.on("exit", (code) => {
    if (stopping) return;
    console.error(`\n${name} stopped unexpectedly (exit code ${code}).`);
    stopAll(1);
  });
  children.push(child);
}

async function waitFor(url, name, seconds) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((wake) => setTimeout(wake, 500));
  }
  console.error(`\n${name} did not start within ${seconds} seconds.`);
  stopAll(1);
}

process.on("SIGINT", () => stopAll(0));
process.on("SIGTERM", () => stopAll(0));

await assertPortFree(API_PORT);
await assertPortFree(WEB_PORT);
setUpApi();
setUpWeb();

if (process.argv.includes("--reset")) {
  step("Deleting the local database");
  for (const suffix of ["", "-wal", "-shm"]) rmSync(join(apiDir, `cep.db${suffix}`), { force: true });
}

step("Applying database migrations");
execFileSync(venvPython, ["-m", "alembic", "upgrade", "head"], { cwd: apiDir, env, stdio: "inherit" });

step("Starting the API and web app");
start("api", venvPython, ["-m", "uvicorn", "app.main:app", "--port", String(API_PORT)], apiDir);
await waitFor(`http://localhost:${API_PORT}/health`, "The API", 60);
start("web", process.execPath, [join(webDir, "node_modules/next/dist/bin/next"), "dev", "-p", String(WEB_PORT)], webDir);
await waitFor(`http://localhost:${WEB_PORT}`, "The web app", 120);

console.log(`
Energy Passport is running on mock data. Press Ctrl+C to stop.

  Web app    http://localhost:${WEB_PORT}
  Wallet     http://localhost:${WEB_PORT}/wallet
  Verifier   http://localhost:${WEB_PORT}/verifier
  Admin      http://localhost:${WEB_PORT}/admin
  API docs   http://localhost:${API_PORT}/docs

  Staff sign-in    admin, operator or auditor / ChangeMe-Dev-Only-1
  Consumer sign-in 1100000001 (the code appears on screen in dev)
                   1100000002 battery and EV charger
                   1100000003 meter only
                   1100000004 blocked by data-quality issues
                   1100000005 solar with no inspection record
`);
