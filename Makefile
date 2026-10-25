GO ?= go
export GOWORK := off

.PHONY: build test lint gates check e2e

build:
	$(GO) build -o build/xdial ./cmd/xdial

test:
	$(GO) test -race ./...

lint:
	test -z "$$(gofmt -l . | tee /dev/stderr)"
	$(GO) vet ./...
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
	@if command -v golangci-lint > /dev/null; then golangci-lint run; else echo "golangci-lint 未安装，跳过（CI 会跑）"; fi

# 推送前就查公开内容：仓库是公开的，推上去就公开了。有 origin/main 时连本分支的历史一起查。
gates:
	bash scripts/check-deps.sh
	@base="$$(git merge-base origin/main HEAD 2> /dev/null || true)"; \
	  PUBLIC_CONTENT_RANGE="$${base:+$$base..HEAD}" bash scripts/check-public-content.sh

# 提 PR 前的本机检查，和 CI 的 go 任务一致（golangci-lint 本机装了才跑）。
check: lint test gates

# 在 mbp64k 的测试虚拟机里跑 e2e，见 docs/agent/e2e.md。
e2e:
	bash scripts/e2e-vm.sh
