// c8s-verify-js against the live front door: TDX image pin, fresh evidence,
// the served allowlist pinned and matched to the expected bytes, the router's
// matched-workload stamp, then GET /v1/models through the tunnel.
import { readFileSync } from "node:fs";
import { request } from "node:https";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const { values: a } = parseArgs({
  options: Object.fromEntries(
    ["url", "server-name", "mode", "image-manifest", "workload", "api-key-file", "allowlist"].map((k) => [k, { type: "string" }]),
  ),
});
for (const [k, v] of Object.entries(a)) if (!v) throw new Error(`--${k} is required`);

const { C8sClient, parseImageManifest } = await import(
  pathToFileURL(join(process.env.VERIFY_JS_SRC, "src", "index.ts")).href
);

// The front door's TLS leaf is CDS-issued for c8s.local and reached by IP, so
// the transport is not WebPKI-verifiable. Trust comes from attest-pq: the
// evidence, the stamped mesh leaf and the transcript, all checked below.
function frontDoorFetch(url, init = {}) {
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      { method: init.method ?? "GET", headers: init.headers, servername: a["server-name"], rejectUnauthorized: false },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("error", reject);
        res.on("end", () => {
          const body = Buffer.concat(chunks);
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
            json: async () => JSON.parse(body.toString("utf8")),
          });
        });
      },
    );
    req.on("error", reject);
    req.end(init.body === undefined ? undefined : Buffer.from(init.body));
  });
}

const served = await frontDoorFetch(`${a.url}/allowlist`);
if (!served.ok) throw new Error(`GET /allowlist: HTTP ${served.status}`);
const allowlist = new Uint8Array(await served.arrayBuffer());
if (!Buffer.from(allowlist).equals(readFileSync(a.allowlist))) {
  throw new Error(`/allowlist bytes differ from ${a.allowlist}`);
}

const client = new C8sClient({
  baseUrl: a.url,
  fetch: frontDoorFetch,
  platform: "tdx",
  tdxImage: parseImageManifest(readFileSync(a["image-manifest"])),
  requireFreshness: true,
  allowlist,
  workloadName: a.workload,
});

// The router's stamp follows allowlist writes within the get-cert renewal
// backoff (up to 30s), so allow a few rounds, as the TEErminator check does.
let session;
for (let attempt = 1; ; attempt++) {
  try {
    session = await client.connect();
    break;
  } catch (err) {
    if (attempt === 12) throw err;
    console.log(`attempt ${attempt}: ${err.code ?? ""} ${err.message}`);
    await new Promise((r) => setTimeout(r, 10_000));
  }
}
const at = session.attestation;
const problems = [];
if (at.platform !== "tdx") problems.push(`platform ${at.platform}, want tdx`);
if (!at.identityBound) problems.push("the identity transcript is not bound into the evidence");
if (at.frontDoorMode !== a.mode) problems.push(`front-door mode ${at.frontDoorMode}, want ${a.mode}`);
if (at.workload?.name !== a.workload) problems.push(`stamped workload ${at.workload?.name}, want ${a.workload}`);
if (problems.length) throw new Error(problems.join("; "));

const apiKey = readFileSync(a["api-key-file"], "utf8");
const res = await session.fetch("/v1/models", { headers: { authorization: `Bearer ${apiKey}` } });
if (res.status !== 200) throw new Error(`tunnel GET /v1/models: HTTP ${res.status}: ${res.text().slice(0, 300)}`);
const models = JSON.parse(res.text());
if (!models.data?.length) throw new Error("tunnel GET /v1/models listed no models");
console.log(
  `ok: c8s-verify-js verified ${a.workload} (tdx, ${a.mode} front door, ${at.trustClass}) and listed ${models.data[0].id} through the tunnel`,
);
for (const w of at.warnings) console.log(`warning: ${w}`);
