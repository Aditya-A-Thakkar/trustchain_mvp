# Phase 2 static-check test fixtures

The tests create temporary, inert fixtures at runtime rather than storing executable malware or real credentials in the repository.

Coverage includes:
- CSV formula-injection-like expressions and valid signed numeric values
- hidden Unicode and prompt-injection indicators in agent text
- secret-pattern detection without echoing secret values in evidence
- legacy model-weight policy hard blocks and safetensors recognition
- dependency-manifest visibility and NOT_CHECKED semantics
- archive structural checks

These are detector regression tests, not a proof of artifact safety. Third-party scanner results depend on the versions and availability of those tools in the runtime.
