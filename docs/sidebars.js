module.exports = {
  docs: [
    "secure-boot",
    {
      type: "category",
      label: "IoT Secure Hub Whitepaper",
      items: [
        {
          type: "category",
          label: "Common",
          items: [
            "white-paper/common/0 - index",
            "white-paper/common/1 - SIR-interop",
            "white-paper/common/2 - Key Architecture Elements",
            "white-paper/common/3 - ProtocolBridge",
            "white-paper/common/5 - IOTH Trust Boundary",
            "white-paper/common/7 - SONA model",
          ],
        },
        {
          type: "category",
          label: "SIR",
          items: [
            "white-paper/SIR/sir-intro",
            "white-paper/SIR/sir-roots-of-trust",
            "white-paper/SIR/sir-network-isolation",
            "white-paper/SIR/sir-device-updates",
          ],
        },
        {
          type: "category",
          label: "DIAD",
          items: [
            "white-paper/DIAD/1-diad-overview",
            "white-paper/DIAD/2-diad-external-identity-flow",
            "white-paper/DIAD/3-diad-architecture",
            "white-paper/DIAD/4-diad-anomaly-workflow",
            "white-paper/DIAD/5-diad-db",
          ],
        },
        {
          type: "category",
          label: "ISM",
          items: [
            "white-paper/ISM/1-ism-intro",
            "white-paper/ISM/2-ism-secure-binding-usecases",
            "white-paper/ISM/3-ism-certificate-semantics",
            "white-paper/ISM/4-ism-bind-overview",
            "white-paper/ISM/5-ism-bind-connect-flow",
            "white-paper/ISM/6-ism-resources",
          ],
        },
      ],
    },
  ],
};
