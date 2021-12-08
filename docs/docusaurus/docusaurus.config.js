module.exports = {
  title: "EDGESec NGI Pointer Project",
  tagline: "EDGESec will define a new architecture for local (edge based) routers addressing fundamental security weaknesses that impact current IP and IOT router implementations",
  url: "https://nqminds.github.io",
  baseUrl: "/", // usually your repo name, must contain a trailing and starting slash
  favicon: "img/logo.svg",
  organizationName: "nqmcyber", // Usually your GitHub org/user name.
  projectName: "edgesec", // Usually your repo name.
  themeConfig: {
    navbar: {
      title: "EDGESec",
      logo: {
        alt: "NQM Docusaurus Template Logo",
        src: "img/logo.svg",
      },
      items: [
        {
          // WARNING, if you change routeBasePath of docs, you should change this as well
          to: "docs/",
          activeBasePath: "docs",
          label: "Docs",
          position: "left",
        },
        {
          // WARNING, if you change routeBasePath of docs, you should change this as well
          to: "docs/about",
          label: "About",
          position: "right",
        },
        {
          href: "https://github.com/nqminds/edgesec",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Contact Us",
          items: [
            {
              label: "Website",
              href: "http://nqmcyber.com",
            },
          ],
        },
      ],
      logo: {
        alt: "NquiringMinds Logo",
        src: "img/nqminds-logo.svg",
        href: "http://nqmcyber.com",
      },
      copyright: `Copyright © ${new Date().getFullYear()} NQMCyber LTD. Built with Docusaurus.`,
    },
  },
  presets: [
    [
      "@docusaurus/preset-classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      {
        docs: {
          routeBasePath: "/docs", // set to "/" if you want to link directly to docs
          sidebarPath: require.resolve("./sidebars.js"),
          // Please change this to your repo.
          editUrl:
            "https://github.com/nqminds/docusaurus-template/edit/master/",
          remarkPlugins: [
            // renders all mermaid code-blocks found in markdown files
            [require("remark-mermaid-dataurl"), {}],
          ],
        },
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
      },
    ],
  ],
  plugins: [require.resolve("docusaurus-lunr-search")],
};
