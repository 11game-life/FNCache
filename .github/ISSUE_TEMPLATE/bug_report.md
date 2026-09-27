---
name: Bug report
about: 报告可复现的问题
title: "[Bug] "
labels: ""
assignees: ""
---

## 问题摘要

<!-- 用一句话描述问题。 -->

## 版本和环境

- Version / commit:
- OS / kernel:
- Architecture:
- Kubernetes / K3s:
- Flannel:
- containerd:
- iptables backend:

## 复现步骤

1.
2.
3.

## 实际行为

<!-- 包括错误信息、异常转发、状态变化或数据面行为。 -->

## 预期行为

<!-- 说明正确结果以及 Flannel fallback 是否应保持可用。 -->

## 诊断信息

<!-- 请删除敏感信息后粘贴日志或结果。适用时附上 bpftool、tc、Map/pin、ownership state 等信息。 -->

~~~text
paste logs or diagnostic output here
~~~

## 影响范围

- [ ] 只影响 ONCache 加速
- [ ] Flannel fallback 仍然正常
- [ ] 影响基础网络连通性
- [ ] 可能涉及安全或对象 ownership
