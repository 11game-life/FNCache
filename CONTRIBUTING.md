# Contributing to FNCache

感谢参与 FNCache。项目目前处于实验性阶段，主要面向 Flannel VXLAN、containerd、IPv4 和 amd64 环境。贡献应优先保证基础网络连通性和安全旁路，再考虑性能收益。

## 贡献流程

1. 先搜索已有 Issue 和 PR，避免重复工作。
2. Bug 或 Feature 先提交 Issue，明确问题、范围和验收方式。
3. 从最新的 master 创建独立分支。
4. 只实现当前 Issue 的目标，避免顺手重构或修复无关问题。
5. 运行与改动相关的检查和测试。
6. 使用 PR 模板提交，并在 Review 中根据反馈继续修改。

一个 Issue 对应一个目标，一个 PR 对应一个独立分支。需要扩大范围时，应先更新 Issue 并重新确认方案。

## 分支和 Commit

分支名使用简短的目的前缀，例如：

~~~text
feat/<short-name>
fix/<short-name>
docs/<short-name>
test/<short-name>
~~~

Commit 使用 Conventional Commits 风格：

~~~text
feat(controlplane): add endpoint reconciliation
fix(datapath): preserve fallback on helper failure
docs: add contribution guidelines
test(integration): cover TC conflict recovery
~~~

不要直接在 master 上开发，不要使用 force push，也不要把多个无关目标合并到同一个 PR。

## 提交前检查

Go 代码改动至少运行：

~~~bash
gofmt -l .
go mod tidy -diff
go vet ./...
go test -race -covermode=atomic -coverprofile=coverage.out ./...
go build ./...
~~~

BPF、TC 或 ABI 改动还应在隔离的 Linux VM 中运行相关检查。下面的示例使用可写的临时构建目录，并显式传入构建工具参数：

~~~bash
BUILD_ROOT="$(mktemp -d /tmp/fncache-build.XXXXXX)"

make -C bpf \
  CLANG=clang \
  LLC=llc \
  BUILD_DIR="$BUILD_ROOT/bpf" \
  all

make -C tests \
  CC=gcc \
  BUILD_DIR="$BUILD_ROOT/tests" \
  test

make -C tests \
  CC=gcc \
  CLANG=clang \
  LLC=llc \
  BUILD_DIR="$BUILD_ROOT/tests" \
  RUN="sudo -n" \
  test-bpf
~~~

涉及真实 netns、TC 或 VXLAN 的改动还应运行：

~~~bash
make -C tests \
  CC=gcc \
  CLANG=clang \
  LLC=llc \
  BUILD_DIR="$BUILD_ROOT/tests" \
  RUN="sudo -n" \
  test-m2-integration
~~~

需要真实 netns、TC、VXLAN 或 bpffs 的测试不得直接在共享宿主机执行。此类测试应使用隔离 VM，并记录内核、工具链、Kubernetes/K3s、Flannel 和 containerd 版本。

## 特殊注意事项

- 涉及 BPF ABI、Map、pin 路径、TC priority/handle、程序 ownership 或 heartbeat 时，必须在 PR 中说明影响。
- 数据面异常必须保持 enabled=0 或回到 Flannel fallback，不能为了提高命中率猜测运行期网络状态。
- 不得覆盖、删除或接管无法证明归 FNCache 所有的 TC、BPF、iptables 或 clsact 对象。
- 配置、状态文件和诊断输出中不得提交凭据或敏感信息。
- 保留工作区中与当前任务无关的已有修改，不要擅自 stash、reset、rebase 或清理。

## PR 要求

PR 至少应说明：

- 解决的问题和关联 Issue；
- 实际修改范围及未包含的内容；
- 测试命令和结果；
- 兼容性、风险和回滚方式；
- 是否影响 BPF ABI、Map、TC ownership 或 fallback。

文档、测试和行为变化应在同一个 PR 中保持一致。未运行的测试必须明确说明原因。
