// Starts the API on a throwaway database, through the real Alembic migration.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const apiDir = resolve(import.meta.dirname, "../../api");
const python = join(apiDir, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
const scratch = mkdtempSync(join(tmpdir(), "cep-e2e-"));
const env = {
  ...process.env,
  CEP_DATABASE_URL: `sqlite+aiosqlite:///${join(scratch, "e2e.db").replaceAll("\\", "/")}`,
  CEP_KEY_PATH: join(scratch, "issuer-key.pem"),
};

execFileSync(python, ["-m", "alembic", "upgrade", "head"], { cwd: apiDir, env, stdio: "inherit" });
const server = spawn(python, ["-m", "uvicorn", "app.main:app", "--port", "8000"], { cwd: apiDir, env, stdio: "inherit" });
const stop = () => server.kill();
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
server.on("exit", (code) => process.exit(code ?? 0));
