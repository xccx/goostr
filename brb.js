const http = require("http");
http.createServer((req, res) => {
  res.writeHead(200, {"Content-Type": "text/html"});
  res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>brb</title></head>
<body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#000;color:#666;font:48px monospace">
brb
</body></html>`);
}).listen(3000, "127.0.0.1", () => console.log("brb mode"));
