"use strict";
// Ollama local-model client — chat, model listing, and coder-model selection.
// Talks to the local Ollama HTTP API (127.0.0.1:11434 by default). The agentic
// tool loop that USES this (ollamaExec) stays in sentinel.js; this is the transport.
const http = require("http");
const HOST = () => process.env.OLLAMA_HOST || "127.0.0.1";
const PORT = () => +(process.env.OLLAMA_PORT || 11434);

function ollamaChat(model, messages, format, signal) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model, stream: false, format, keep_alive: "30m", options: { temperature: 0.2, num_ctx: 16384 }, messages });
    const req = http.request({ host: HOST(), port: PORT(), path: "/api/chat", method: "POST", signal, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (res) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve(JSON.parse(d).message.content || ""); } catch (e) { reject(new Error("bad model response")); } }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => { req.destroy(new Error("Ollama timed out (no response) — is the model stuck loading?")); });
    req.on("error", (e) => reject(new Error("cannot reach Ollama at " + HOST() + ":" + PORT() + " — is it running? (" + e.message + ")"))); req.write(body); req.end();
  });
}
function ollamaTags() {
  return new Promise((resolve) => {
    http.get({ host: HOST(), port: PORT(), path: "/api/tags" }, (res) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve((JSON.parse(d).models || []).map((m) => m.name)); } catch (_) { resolve([]); } }); }).on("error", () => resolve([]));
  });
}
// Pick the best available local model for coding: prefer known coder models, then
// anything named code-ish, else the first installed model.
function pickCoderModel(ms) {
  ms = ms || [];
  const pri = ["qwen2.5-coder", "deepseek-coder", "codellama", "hermes3", "dolphin3", "llama3.1"];
  for (const p of pri) { const hit = ms.find((m) => m.toLowerCase().startsWith(p)); if (hit) return hit; }
  return ms.find((m) => /coder|code/i.test(m)) || ms[0] || "";
}
module.exports = { ollamaChat, ollamaTags, pickCoderModel };
