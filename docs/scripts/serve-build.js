const express = require("express");
const docusaursConfig = require("../docusaurus.config.js");

async function main() {
  const app = express();
  const route = docusaursConfig.baseUrl;
  app.use(route, express.static("build"));

    // we pick a random port, since 3000 will probably be used by the dev server
  const server = await app.listen();
  console.log(`Listening on http://localhost:${server.address().port}${route}`);
}

main().catch((error) => console.error(error));
