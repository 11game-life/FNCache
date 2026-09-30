# Contributing to FNCache

Thank you for contributing to FNCache. The project is experimental and primarily targets Flannel VXLAN, containerd, IPv4, and amd64 environments. Contributions should preserve basic network connectivity and safe fallback behavior before pursuing performance improvements.

## Contribution workflow

1. Search existing Issues and pull requests to avoid duplicate work.
2. Open an Issue for a bug or feature, describing its scope and acceptance criteria.
   You may create an Issue yourself, or claim an existing one by commenting `/assign`.
   Wait for maintainer confirmation after claiming to avoid duplicate work.
3. Create an independent branch from the latest master.
4. Implement only the current Issue goal. Do not include unrelated refactoring or fixes.
5. Run checks and tests relevant to the change.
6. Open a pull request using the repository template and respond to review feedback.

One Issue should represent one goal, and one pull request should use one dedicated branch. If the scope must expand, update the Issue and confirm the revised plan first.

## Branches and commits

Use a short purpose-based branch prefix, for example:

~~~text
feat/<short-name>
fix/<short-name>
docs/<short-name>
test/<short-name>
~~~

Use the Conventional Commits style:

~~~text
feat(controlplane): add endpoint reconciliation
fix(datapath): preserve fallback on helper failure
docs: add contribution guidelines
test(integration): cover TC conflict recovery
~~~

Do not develop directly on master, use force push, or combine unrelated goals in one pull request.

## Checks before submission

Go changes should run at least:

~~~bash
gofmt -l .
go mod tidy -diff
go vet ./...
go test -race -covermode=atomic -coverprofile=coverage.out ./...
go build ./...
~~~

BPF, TC, or ABI changes should also run the relevant checks in an isolated Linux VM. The examples below use a writable temporary build directory and explicitly pass the build tools:

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

Changes involving real network namespaces, TC, or VXLAN should also run:

~~~bash
BUILD_ROOT="$(mktemp -d /tmp/fncache-build.XXXXXX)"

make -C tests \
  CC=gcc \
  CLANG=clang \
  LLC=llc \
  BUILD_DIR="$BUILD_ROOT/tests" \
  RUN="sudo -n" \
  test-m2-integration
~~~

Tests requiring real network namespaces, TC, VXLAN, or bpffs must not run directly on a shared host. Use an isolated VM and record the kernel, toolchain, Kubernetes/K3s, Flannel, and containerd versions.

## Special considerations

- Explain the impact of changes involving the BPF ABI, Maps, pin paths, TC priority/handles, program ownership, or heartbeat behavior.
- If datapath state is uncertain, keep enabled=0 or fall back to Flannel. Do not guess runtime network state to improve the hit rate.
- Do not overwrite, delete, or take ownership of TC, BPF, iptables, or clsact objects that cannot be proven to belong to FNCache.
- Do not commit credentials or sensitive information in configuration, state files, or diagnostic output.
- Preserve unrelated existing worktree changes. Do not run stash, reset, rebase, or cleanup commands without confirmation.

## Pull request requirements

Every pull request should explain:

- the problem being solved and the related Issue;
- the actual change scope and what is intentionally excluded;
- the test commands and results;
- compatibility, risk, and rollback information;
- whether the BPF ABI, Maps, TC ownership, or fallback behavior is affected.

Keep documentation, tests, and behavior changes consistent within the same pull request. Clearly state why any test was not run.
