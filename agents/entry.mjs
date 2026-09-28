// labsOBO | container entrypoint: one image, two AgentCore runtimes. LABSOBO_ROLE=a1 (default) | broker.
const role = process.env.LABSOBO_ROLE ?? "a1";
await import(role === "broker" ? "./jira-broker/server.mjs" : "./agent1-local/server.mjs");
