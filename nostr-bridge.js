// nostr-bridge.js - connects to strfry, logs events to SHIT
//
// DESIGN: nostr as transport layer, not application layer
// - strfry relay runs locally (ws://127.0.0.1:7777)
// - we subscribe to kind:1 (text notes) and log to SHIT format
// - could swap strfry for any pubsub; nostr chosen for existing ecosystem
//
// SHIT LINE FORMAT: WHEN WHERE WHO WHAT
// - WHEN: unix ms (not seconds) — enables sub-second ordering
// - WHERE: event id truncated to 16 hex chars — enough for collision resistance
// - WHO: "n:" + pubkey prefix — identifies poster, linkable to full npub
// - WHAT: content, newlines stripped, max 500 chars
//
// TRADEOFF: we trust strfry to deliver events; no proof of delivery
// TRADEOFF: 16-char WHERE is 64 bits — birthday collision at ~4B events
//
const WebSocket = require("ws");
const fs = require("fs");
const crypto = require("crypto");

const RELAY = "ws://127.0.0.1:7777";
const LOG = "/root/.shit.log";

function connect() {
  console.log("Connecting to strfry...");
  const ws = new WebSocket(RELAY);
  
  ws.on("open", () => {
    console.log("Connected. Subscribing to all kind:1 events...");
    ws.send(JSON.stringify(["REQ", "bridge", { kinds: [1] }]));
  });
  
  ws.on("message", (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg[0] === "EVENT" && msg[2]) {
        const event = msg[2];
        const when = event.created_at * 1000; // ms
        const where = event.id.slice(0, 16); // event id as WHERE
        const who = "n:" + event.pubkey.slice(0, 12); // npub prefix
        const what = event.content.replace(/\n/g, " ").slice(0, 500);
        
        if (what.trim()) {
          const line = `${when} ${where} ${who} ${what}`;
          fs.appendFileSync(LOG, line + "\n");
          console.log("Logged:", line.slice(0, 80) + "...");
        }
      }
    } catch (e) {
      console.error("Parse error:", e.message);
    }
  });
  
  ws.on("close", () => {
    console.log("Disconnected. Reconnecting in 5s...");
    setTimeout(connect, 5000);
  });
  
  ws.on("error", (err) => {
    console.error("WS error:", err.message);
  });
}

connect();
