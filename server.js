const express = require("express");
const { exec } = require("child_process");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: 8000 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        output: (stdout || stderr || "").trim(),
      });
    });
  });
}

app.get("/api/health", async (_req, res) => {
  const status = await run("openclaw status");
  res.json({
    timestamp: new Date().toISOString(),
    openclaw: status.ok ? "up" : "down",
    raw: status.output,
  });
});

app.post("/api/restart", async (_req, res) => {
  const restart = await run("openclaw gateway restart");
  res.json({
    success: restart.ok,
    message: restart.ok ? "Gateway restarted" : "Restart failed",
    raw: restart.output,
  });
});

app.listen(PORT, () => {
  console.log(`Dashboard running on http://localhost:${PORT}`);
});
