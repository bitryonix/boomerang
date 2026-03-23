# poc-runtime Limitations

- The supported PoC path still assumes a local Bitcoin Core node and the current TCP transport.
- The launcher is development-oriented and not yet a general multi-host supervisor.
- Legacy reference runners still exist under `poc/`, so the repository intentionally keeps older
  PoC paths beside the supported one for regression and design comparison.
- The terminal narrative is intentionally summarized; exact per-process details still require the
  on-disk logs in the run directory.
