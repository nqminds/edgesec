module.exports = {
  title: "NquiringMinds Docusaurus Template",
  tagline: "A template for creating docusaurus sites in NquiringMinds",
  url: "https://nqminds.github.io",
  baseUrl: "/docusaurus-template/", // usually your repo name, must contain a trailing and starting slash
  favicon: "img/logo.svg",
  organizationName: "nqminds", // Usually your GitHub org/user name.
  projectName: "docusaurus-template", // Usually your repo name.
  themeConfig: {
    navbar: {
      title: "NQM Docusaurus Template",
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
          href: "https://github.com/nqminds/docusaurus-template",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            {
              label: "Index",
              to: "/",
            },
          ],
        },
        {
          title: "Contact Us",
          items: [
            {
              label: "Website",
              href: "https://nquiringminds.com",
            },
            {
              label: "Twitter",
              href: "https://twitter.com/nqminds",
            },
          ],
        },
      ],
      logo: {
        alt: "NquiringMinds Logo",
        src: "img/nqminds-logo.svg",
        href: "https://nquiringminds.com",
      },
      copyright: `Copyright © ${new Date().getFullYear()} NquiringMinds LTD. Built with Docusaurus.`,
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
