// Usage: node scripts/tx-status.mjs <txHash>
// Reads a transaction straight through genlayer-js; useful when the CLI's
// receipt polling times out on a flaky connection.
import { createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";
const c = createClient({ chain: testnetBradbury });
const tx = await c.getTransaction({ hash: process.argv[2] });
const pick = (o) => JSON.stringify(o, (k, v) => typeof v === "bigint" ? v.toString() : v);
console.log("status:", tx.statusName ?? tx.status_name ?? tx.status, "result:", tx.resultName ?? tx.result_name ?? tx.result, "exec:", tx.txExecutionResultName);
console.log("contract:", tx.txDataDecoded?.contractAddress ?? tx.recipient ?? tx.to_address);
