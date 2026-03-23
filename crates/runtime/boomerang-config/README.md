# boomerang-config

Owns POC defaults, topology config, withdrawal config, process manifests, cluster manifests, and
the public WT/SAR identity artifact shape used by the supported runtime path.

WT/SAR process manifests now carry only the runtime inputs WT/SAR need to initialize themselves.
WT/SAR create private identity material internally during `run`, and the only non-core identity
artifact on disk is `state_dir/identity-public.toml`.

Legacy WT/SAR manifests that still contain `private_key`, `tor_secret_key`, `wt_id`, or `sar_id`
inside WT/SAR bootstrap payloads are now rejected during config loading with a migration error.

The configuration layer now describes public and operator-facing state only. WT/SAR private
identity material is intentionally outside this crate’s manifest schema.
