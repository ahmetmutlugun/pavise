import { defineRailway, github, preserve, project, service } from "railway/iac";

export default defineRailway(() => {
  const pavise = service("pavise", {
    source: github("ahmetmutlugun/pavise", { checkSuites: false }),
    build: { buildEnvironment: "V3", builder: "DOCKERFILE", dockerfilePath: "Dockerfile", watchPatterns: ["src/**", "rules/**", "templates/**", "assets/**", "data/**", "web/**", "Cargo.toml", "Cargo.lock", "Dockerfile", ".dockerignore"] },
    healthcheck: "/healthz",
    healthcheckTimeout: 60,
    replicas: { "us-west2": 1 },
    deploy: { limitOverride: { containers: { cpu: 1, memoryBytes: 1000000000 } }, restartPolicyMaxRetries: 5 },
    domains: [{ domain: "pavise.app", port: 3000 }],
    env: { PAVISE_CACHE_MAX_ENTRIES: preserve(), PAVISE_EDGE_SECRET: preserve(), PAVISE_MAX_IN_FLIGHT_BYTES: preserve(), PAVISE_MAX_PDF: preserve(), PAVISE_MAX_SCANS: preserve(), PAVISE_TRUSTED_PROXY: preserve(), PORT: preserve() },
  });

  return project("incredible-clarity", {
    resources: [pavise],
  });
});
