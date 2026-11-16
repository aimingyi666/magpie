import { startServer } from "../corp-server/src/server.mjs";

const server = startServer({ port: Number(process.env.CORP_PORT || 62337) });
const port = await server.listening;
console.log(`corp_port=${port}`);
process.stdin.resume();
