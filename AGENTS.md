# Agent Notes

## Releases

- `bumpp` can be run non-interactively with `--yes` (`-y`) to skip confirmation and `--release <type>` to specify the version bump (for example, `bumpp --yes --release patch`).
- The release script in `package.json` runs `bumpp`, reads the version with Node.js, and creates the matching GitHub release.
