/**
 * labsOBO | A1's tool registry, read at runtime.
 *
 * A1's code names no resource, endpoint or permission. Each tool it can use is an entry in a registry
 * kept outside the image, in AWS SSM Parameter Store (LABSOBO_TOOL_REGISTRY=ssm:<parameter name>):
 *   { "<tool id>": { "resource": "<Entra resource URI>", "endpoint": "<URL A1 calls>" } }
 * The permissions are not in the registry either. A1 asks Entra for <resource>/.default on behalf of the
 * user, and Entra puts into the token exactly the delegated scopes an admin consented for A1 on that
 * resource; A1 reads them from the token's scp claim. Change the consent and the next token changes;
 * change the registry and A1 uses it within a minute. Neither needs a redeploy.
 */
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { env, cfg } from "./entra.mjs";

const SOURCE = process.env.LABSOBO_TOOL_REGISTRY ?? env.LABSOBO_TOOL_REGISTRY ?? null;
const TTL_MS = 60000;
let cache = null;

async function registry() {
  if (cache && Date.now() - cache.at < TTL_MS) return { ...cache, cached: true };
  if (!SOURCE?.startsWith("ssm:")) throw new Error("LABSOBO_TOOL_REGISTRY is not set (expected ssm:<parameter name>); run scripts/57-tool-registry.sh");
  const name = SOURCE.slice(4);
  const t0 = Date.now();
  const r = await new SSMClient({ region: process.env.AWS_REGION ?? cfg.aws.region }).send(new GetParameterCommand({ Name: name }));
  cache = { at: Date.now(), name, version: r.Parameter.Version, modified: r.Parameter.LastModifiedDate, entries: JSON.parse(r.Parameter.Value), ms: Date.now() - t0 };
  return { ...cache, cached: false };
}

/** Resolve one tool: { id, resource, endpoint, registry: { name, version, cached, ms } }. */
export async function tool(id) {
  const reg = await registry();
  const t = reg.entries[id];
  if (!t?.resource || !t?.endpoint) throw new Error(`the tool registry ${reg.name} (v${reg.version}) has no usable entry "${id}"`);
  return { id, resource: t.resource, endpoint: t.endpoint, registry: { name: reg.name, version: reg.version, cached: reg.cached, ms: reg.ms } };
}
