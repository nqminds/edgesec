"use strict"

const express = require("express");
const log = require("debug")("rest");
const net = require("net");
const app = express();
const port = Number(process.argv[2] || "3000");
const domainSocketname = process.argv[3] || "/home/alexandru/Projects/EDGESec/build/revcontrol";

log(`Domain socket path=${domainSocketname}`);

app.get("/", (req, res) => {
  const client = net.createConnection(domainSocketname,
    () => {
      log("connected to server!");
      client.write("[] CLIENTS");
    }
  );

  client.on("data", (data) => {
    log(data.toString());
    res.send(data.toString());
    client.end();
  });

  client.on("end", () => {
    log("disconnected from server");
  });
})

app.get("/api", (req, res) => {
  log(req.query);
  res.send("Hello World!");
})
  
app.listen(port, () => {
  log(`Example app listening at http://localhost:${port}`);
})
