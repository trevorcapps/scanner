# Releasing and versioning

## Versioning

Artemis follows [Semantic Versioning](https://semver.org/) once it reaches
1.0. Before 1.0, `MINOR` bumps may contain breaking changes; `PATCH` bumps do
not.

- The single source of the version is `pyproject.toml` → `project.version`.
- `artemis/__init__.py` and the `/api/v1/health` payload read that value; do
  not hard-code a version anywhere else.
- The REST API is versioned in the URL (`/api/v1`). A breaking API change ships
  under a new path segment with a documented deprecation window for the old one.

## Database and worker compatibility

- A release must run against the immediately previous release's database after
  `flask db upgrade`.
- The web and worker images in a deployment must be the same version. CI's
  migration/worker compatibility check enforces this; the entrypoint refuses to
  start a worker whose code is older than the applied migration head.

## Release process

1. Ensure `master` is green (all required checks).
2. Bump `project.version` in `pyproject.toml`; update `ROADMAP.md` /
   `CHANGELOG` notes.
3. Regenerate lock files if dependencies changed (`./scripts/lock-deps.sh`).
4. Open a release PR; merge once approved.
5. Tag `vX.Y.Z` on the merge commit. Tags matching `v*` are **protected** and
   trigger the release workflow.

## What the release workflow does (on a protected `v*` tag)

- Builds the production image and pins it by digest.
- Generates an SBOM (CycloneDX) for the image and the Python environment.
- Signs the image and the SBOM.
- Publishes the image, SBOM, and signatures as immutable release artifacts.
- **Does not deploy.** Deployment to any environment requires a separate,
  manually approved workflow run (D10). No pipeline pushes to production
  automatically.

## Hotfixes

Branch from the release tag, apply the minimal fix with a migration if needed,
tag `vX.Y.(Z+1)`, and forward-port to `master` in the same PR series.
