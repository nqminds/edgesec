"use strict"

import {UnixDgramSocket} from "unix-dgram-socket";
import express from "express";
import Debug from "debug";
import passport from "passport";
import localApiKey from "passport-localapikey";
import cookieParser  from "cookie-parser";
import bodyParser from "body-parser";
import methodOverride from "method-override";
import session from "express-session";
import URLSafeBase64 from "urlsafe-base64";

import config from "./config.js";

const LocalStrategy = localApiKey.Strategy;
const log = Debug("rest");
const app = express();
const {port, serverSocketname, clientSocketname, users} = config;

function findById(id, fn) {
  const idx = id - 1;
  if (users[idx]) {
    fn(null, users[idx]);
  } else {
    fn(Error(`User ${id} does not exist`));
  }
}

function findByUsername(username, fn) {
  for (let i = 0, len = users.length; i < len; i++) {
    const user = users[i];
    if (user.username === username) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}

function findByApiKey(apikey, fn) {
  for (const i = 0, len = users.length; i < len; i++) {
    const user = users[i];
    if (user.apikey === apikey) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
  findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy(
  function(apikey, done) {
    process.nextTick(function () {      
      findByApiKey(apikey, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false, {message: `Unknown apikey: ${apikey}`}); }
        return done(null, user);
      })
    });
  }
));

// configure Express
app.use(cookieParser());
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
 
// parse application/json
app.use(bodyParser.json())
app.use(methodOverride());
app.use(session({ secret: "keyboard uber cat"}));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect("/unauthorized")
}

function convertToStrArray(data) {
  return data.split("\n").map((row) => row.split(" "));
}

function checkSafeFile(name) {
  return (name.indexOf("/") < 0);
}

function getDomainData(command, callback) {
  const socket = new UnixDgramSocket();

  // Call on error
  socket.on("error", (error) => {
    callback({}, error);
    socket.close();
  });

  // Call when new message is received
  socket.on("message", (message, info) => {
    const data = message.toString(UnixDgramSocket.payloadEncoding);
    callback(convertToStrArray(data), null);
    socket.close();
  });

  // Call on successful connect
  socket.on("connect", (path) => {
    log(`socket connected to path: ${path}`);
  });

  // Call when socket is bind to path
  socket.on("listening", (path) => {
    log(`socket listening on path: ${path}`);
  });

  socket.bind(clientSocketname);
  socket.send(command, serverSocketname);
}

log(`Domain socket path=${serverSocketname}`);

app.get("/", ensureAuthenticated, (req, res) => {
  getDomainData("[] CLIENTS", (data, error) => {
    if (error) {
      res.json({ error: error.message });
    } else {
      res.json({response: data});
    }
  });
})

app.get("/first", ensureAuthenticated, (req, res) => {
  const id = req.query.id || "";
  const sqlQuery = URLSafeBase64.encode(Buffer.from("SELECT * FROM pcap ORDER BY timestamp ASC LIMIT 1;"));
  getDomainData(`[${id}] EXEC pcap-meta.sqlite ${sqlQuery}`, (data, error) => {
    if (error) {
      res.json({ error: error.message });
    } else {
      res.json({response: data});
    }
  });
})

app.get("/query", ensureAuthenticated, (req, res) => {
  const id = req.query.id || "";
  const lt = Number(req.query.lt || "0");
  const ht = Number(req.query.ht || "0");

  const sqlQuery = URLSafeBase64.encode(Buffer.from(`SELECT * FROM pcap WHERE timestamp >= ${lt} AND timestamp <= ${ht} ORDER BY timestamp ASC;`));
  getDomainData(`[${id}] EXEC pcap-meta.sqlite ${sqlQuery}`, (data, error) => {
    if (error) {
      res.json({ error: error.message });
    } else {
      res.json({response: data});
    }
  });
})

app.get("/get", ensureAuthenticated, (req, res) => {
  const id = req.query.id || "";
  const file = req.query.file || "";
  
  if (!checkSafeFile(file)) {
    res.json({ error: "Wrong file" });
  } else {
    const filePath = `./pcap/${file}`;

    getDomainData(`[${id}] GET ${filePath}`, (data, error) => {
      if (error) {
        res.json({ error: error.message });
      } else {
        res.json({response: data});
      }
    });  
  }
})
  
app.get("/account", ensureAuthenticated, function(req, res){  
  res.json({response: "Authenticated"})
});
  
app.get("/unauthorized", function(req, res){
  res.json({error: "Authentication Error"})
});

app.post("/authenticate", 
  passport.authenticate("localapikey", { failureRedirect: "/unauthorized", failureFlash: true }),
  function(req, res) {
     res.json({response: "Authenticated"})
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.listen(port, "0.0.0.0", () => {
  log(`Example app listening at http://0.0.0.0:${port}`);
})
