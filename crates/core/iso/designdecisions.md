# iso Design Decisions

- ISO remains a dedicated role crate with transport-independent behavior.
- The setup flow is split by protocol phase rather than by helper type so each file lines up with a concrete ceremony checkpoint.
