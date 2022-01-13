module.exports = {
  title: "EDGESec",
  tagline: "Secure IoT router implementation",
  url: "https://nqminds.github.io",
  baseUrl: "/EDGESec/", // usually your repo name, must contain a trailing and starting slash
  favicon: "img/network.svg",
  organizationName: "nqmcyber", // Usually your GitHub org/user name.
  projectName: "edgesec", // Usually your repo name.
  themeConfig: {
    navbar: {
      title: "EDGESec",
      logo: {
        alt: "NQM Docusaurus Template Logo",
        src: "img/network.svg",
      },
      items: [
        {
          // WARNING, if you change routeBasePath of docs, you should change this as well
          to: "docs/",
          activeBasePath: "docs",
          label: "Documentation",
          position: "left",
        },
        {
          // WARNING, if you change routeBasePath of docs, you should change this as well
          to: "blog/",
          label: "Blog",
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
      copyright: `Copyright © ${new Date().getFullYear()} NQMCyber LTD.<br/>Built with Docusaurus.`,
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
