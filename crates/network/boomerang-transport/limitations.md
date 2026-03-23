# boomerang-transport Limitations

- The current transport uses blocking TCP plus thread-based readers.
- Outbound connect retry policy is intentionally simple and fixed-width.
- Reader threads are detached rather than managed through explicit join handles.
- The transport currently records coarse startup progress lines, not full metrics.

## Future work

- Add richer timeout and backoff configuration per link.
- Add explicit shutdown and join management for reader threads.
- Expand observability with structured transport metrics in addition to progress logs.
