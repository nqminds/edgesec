export default {
  "title": "EDGESec",
  "tagline": "Secure IoT router implementation",
  "url": "https://nqminds.github.io",
  "baseUrl": "/",
  "favicon": "img/logo.svg",
  "organizationName": "nqmcyber",
  "projectName": "edgesec",
  "themeConfig": {
    "navbar": {
      "title": "EDGESec",
      "logo": {
        "alt": "NQM Docusaurus Template Logo",
        "src": "img/logo.svg"
      },
      "items": [
        {
          "to": "docs/",
          "activeBasePath": "docs",
          "label": "Documentation",
          "position": "left"
        },
        {
          "to": "docs/about",
          "label": "About",
          "position": "right"
        },
        {
          "href": "https://github.com/nqminds/edgesec",
          "label": "GitHub",
          "position": "right"
        }
      ],
      "hideOnScroll": false
    },
    "footer": {
      "style": "dark",
      "links": [
        {
          "title": "Contact Us",
          "items": [
            {
              "label": "Website",
              "href": "http://nqmcyber.com"
            }
          ]
        }
      ],
      "copyright": "Copyright © 2021 NQMCyber LTD.<br/>Built with Docusaurus."
    },
    "colorMode": {
      "defaultMode": "light",
      "disableSwitch": false,
      "respectPrefersColorScheme": false,
      "switchConfig": {
        "darkIcon": "🌜",
        "darkIconStyle": {},
        "lightIcon": "🌞",
        "lightIconStyle": {}
      }
    },
    "docs": {
      "versionPersistence": "localStorage"
    },
    "metadatas": [],
    "prism": {
      "additionalLanguages": []
    },
    "hideableSidebar": false,
    "tableOfContents": {
      "minHeadingLevel": 2,
      "maxHeadingLevel": 3
    }
  },
  "presets": [
    [
      "@docusaurus/preset-classic",
      {
        "docs": {
          "routeBasePath": "/docs",
          "sidebarPath": "/home/alexandru/Projects/EDGESec/docs/docusaurus/sidebars.js",
          "editUrl": "https://github.com/nqminds/docusaurus-template/edit/master/",
          "remarkPlugins": [
            [
              null,
              {}
            ]
          ]
        },
        "theme": {
          "customCss": "/home/alexandru/Projects/EDGESec/docs/docusaurus/src/css/custom.css"
        }
      }
    ]
  ],
  "plugins": [
    "/home/alexandru/Projects/EDGESec/docs/docusaurus/node_modules/docusaurus-lunr-search/src/index.js"
  ],
  "baseUrlIssueBanner": true,
  "i18n": {
    "defaultLocale": "en",
    "locales": [
      "en"
    ],
    "localeConfigs": {}
  },
  "onBrokenLinks": "throw",
  "onBrokenMarkdownLinks": "warn",
  "onDuplicateRoutes": "warn",
  "customFields": {},
  "themes": [],
  "titleDelimiter": "|",
  "noIndex": false
};