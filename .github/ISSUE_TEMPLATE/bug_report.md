---
name: Bug report
about: Report a reproducible problem
title: "[Bug] "
labels: ""
assignees: ""
---

## Summary

<!-- Describe the problem in one sentence. -->

## Version and environment

- Version / commit:
- OS / kernel:
- Architecture:
- Kubernetes / K3s:
- Flannel:
- containerd:
- iptables backend:

## Steps to reproduce

1.
2.
3.

## Actual behavior

<!-- Include error messages, unexpected forwarding, state changes, or datapath behavior. -->

## Expected behavior

<!-- Describe the expected result and whether Flannel fallback should remain available. -->

## Diagnostics

<!-- Remove sensitive information before pasting logs or output. When relevant, include bpftool, tc, Map/pin, or ownership state information. -->

~~~text
paste logs or diagnostic output here
~~~

## Impact

- [ ] Affects only ONCache acceleration
- [ ] Flannel fallback remains functional
- [ ] Affects basic network connectivity
- [ ] May involve security or object ownership
