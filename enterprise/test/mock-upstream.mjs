// A minimal OpenAI-compatible upstream for the enterprise E2E tests.
// /__stats counts real chat requests, so tests can prove that a gateway
// refusal never reached the provider.
import http from "node:http";

const port = Number(process.env.PORT || 3499);
let chatRequests = 0;
const chatRequestsByModel = new Map();

function countChat(model) {
  chatRequests += 1;
  chatRequestsByModel.set(model, (chatRequestsByModel.get(model) || 0) + 1);
}

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    if (req.method === "GET" && req.url === "/__stats") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        chatRequests,
        chatRequestsByModel: Object.fromEntries(chatRequestsByModel),
      }));
      return;
    }

    if (req.method === "GET" && req.url === "/v1/models") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        object: "list",
        data: [
          { id: "mock-model", object: "model", owned_by: "enterprise-test" },
          { id: "mock-second", object: "model", owned_by: "enterprise-test" },
        ],
      }));
      return;
    }

    if (req.method === "POST" && req.url.endsWith("/chat/completions")) {
      let parsed = {};
      try {
        parsed = JSON.parse(body || "{}");
      } catch {
        // leave parsed empty; the response still proves routing
      }
      const id = "chatcmpl-mock";
      const now = Math.floor(Date.now() / 1000);
      const model = parsed.model || "mock-model";
      countChat(model);

      if (parsed.stream) {
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          connection: "keep-alive",
        });
        res.write("data: " + JSON.stringify({
          id,
          object: "chat.completion.chunk",
          created: now,
          model,
          choices: [{ index: 0, delta: { role: "assistant", content: "mock-upstream-ok" }, finish_reason: null }],
        }) + "\n\n");
        res.write("data: " + JSON.stringify({
          id,
          object: "chat.completion.chunk",
          created: now,
          model,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }) + "\n\n");
        res.write("data: [DONE]\n\n");
        res.end();
        return;
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        id,
        object: "chat.completion",
        created: now,
        model,
        choices: [{
          index: 0,
          message: { role: "assistant", content: "mock-upstream-ok" },
          finish_reason: "stop",
        }],
        usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
      }));
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { message: "not found" } }));
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log("mock upstream on " + port);
});
