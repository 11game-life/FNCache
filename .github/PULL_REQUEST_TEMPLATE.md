## Summary

<!-- Briefly describe what this pull request solves. -->

## Related Issue

Closes #

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Test
- [ ] CI / Build

## Design and scope

- Root cause or motivation:
- Actual changes:
- Explicitly not included:

## Testing

List the commands actually run and their results. Explain why any test was not run.

~~~text
go test -race ./...
~~~

## eBPF / TC checks

If this pull request touches the datapath, confirm:

- [ ] BPF ABI, Map, or pin path impact is explained
- [ ] TC priority, handle, and program ownership impact is explained
- [ ] Safe fallback to Flannel has been verified for failure paths
- [ ] Relevant privileged tests were run in an isolated Linux VM

## Risk and rollback

- Compatibility risk:
- Runtime risk:
- Rollback procedure:

## Submission checklist

- [ ] This pull request addresses one goal
- [ ] No unrelated refactoring, formatting, or dependency upgrades are included
- [ ] Necessary tests or documentation have been updated
- [ ] No credentials, private configuration, or sensitive logs are included
