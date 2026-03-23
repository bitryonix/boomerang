# boomerang-config Design Decisions

- Runtime manifests and POC defaults were unified in one crate to keep config ownership out of `boomerang-runtime`.
- WT/SAR private identity material was removed from non-core config entirely. The config crate now
  owns only the public identity artifact shape supervisors consume after WT/SAR runtime startup.
