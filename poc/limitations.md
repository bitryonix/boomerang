# PoC Area Limitations

- `poc-runtime` is still a local-development supervisor, not a general production control plane.
- `poc-networked` and `poc-steps` duplicate parts of the supported flow because they remain as
  reference surfaces.
- The curated terminal narrative intentionally trades completeness for readability, so deep
  debugging still requires the per-process log files.
