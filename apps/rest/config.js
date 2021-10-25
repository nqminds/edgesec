let config = {
  "port": 8512,
  "keyFile": "/home/alexandru/Projects/EDGESec/build/cert/CA/server/server.key",
  "certFile": "/home/alexandru/Projects/EDGESec/build/cert/CA/server/server.crt",
  "serverSocketname": "/tmp/revcontrol",
  "clientSocketname": "/tmp/client-rest",
  "users": [
    {id: 1, username: 'bob', apikey: "asdasjsdgfjkjhg"},
    {id: 2, username: 'joe', apikey: "gfsdgsfgsfg"}
  ],
};
export default config;