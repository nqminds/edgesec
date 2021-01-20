# Website

This website is built using [Docusaurus 2](https://v2.docusaurus.io/), a modern static website generator.

- [Installation](#installation)
- [Local Development](#local-development)
- [Build](#build)
- [Deployment](#deployment)
- [Adding Pages](#adding-pages)

### Installation

```console
$ npm install
```

### Local Development

```console
$ npm start
```

This command starts a local development server and open up a browser window. Most changes are reflected live without having to restart the server.

**Warning, the search bar does not work in development mode.**

### Build

```console
$ npm run build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

You can test the build by running:

```console
$ npm run serve-build
```

### Creating a PDF

You can create a PDF using [docusaurus-pdf](https://github.com/KohheePeace/docusaurus-pdf) by running:

_**Warning:** This code has only been tested on Linux_

```
$ npm run pdf
```

### Deployment

Make a pull request to the `master` branch of the GitHub repo.

The GitHub Actions CI script will automatically test that your changes will
compile correctly. You can then merge into `master`, where another GitHub
Actions CI script will deploy this website using GitHub Pages.

### Adding Pages

#### Creating the page

Pages can be added via adding markdown files to the `docs/` folder.

See [Docusaurus Markdown Features](https://v2.docusaurus.io/docs/markdown-features)
for markdown features you can use.

Normally, you'd want to place a markdown header into your document, e.g.
having the following at the beginning of your markdown file:

```yaml
---
id: the-url-id # by default, this it path/to/markdown-file
title: Some Cool Title # the title to use in docusaurus links + tab window
hide_title: true # if you already have your title in the text
---
Example **markdown** content
```

#### Static Files (e.g. images)

_See [Docusaurus Website | Static Assets](https://v2.docusaurus.io/docs/static-assets) for more info_

Images and other static files can be placed in the [`./static](./static)
folder, if you want to host them on the website.

Their url would be the same as their path in the static folder.

E.g., if you place an image in
[./static/images/safe-box.svg](./static/images/safe-box.svg), you can show
it as a markdown image by entering (replaced `/static/` with `/EDGESec/`):

```markdown
![My example image](/EDGESec/images/safe-box.svg)
```

#### Adding to the sidebar

After you make your markdown file, you can make a reference to it in the
sidebar, by editing [`./sidebars.js`](./sidebars.js). You should insert the
`id` of your markdown file.

By default, this id will be the path to your markdown file in the docs folder.
e.g. the id of
[`./docs/tdx-restful-api/nqm-core-query.md`](./docs/tdx-restful-api/nqm-core-query.md)
is `tdx-restful-api/nqm-core-query`.

#### Testing and deploying the page

Follow the steps in [Installation](#installation) and
[Local Development](#local-development) in order to test it locally.

Then follow the steps in [Build](#build) to make sure the static version
works fine.

Finally, commit your changes into a new git branch, push the changes to GitHub,
and follow the steps in [Deployment](#deployment)
to make a [pull request][1]
and deploy the changes.

[1]: https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request
