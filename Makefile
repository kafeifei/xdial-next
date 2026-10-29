GO ?= go
export GOWORK := off

# 构建 tag 见 ARCHITECTURE.md 2.3 和 2.6：不用上游的 include，类型由 XDial 自己的 registry 决定；
# ts_omit_* 去掉 tailscale 自己终结、不经过 sing-box 路由的服务。CI 用同一份。
TAGS := $(shell cat .github/build-tags.txt)
export GOFLAGS := -tags=$(TAGS)
# 和 .github/workflows/ci.yml 里的版本一致。
GOLANGCI_LINT_VERSION := v2.15.0

.PHONY: build test lint gates check e2e app app-test

build:
	$(GO) build -o build/xdial ./cmd/xdial

test:
	$(GO) test -race ./...

lint:
	test -z "$$(gofmt -l . | tee /dev/stderr)"
	$(GO) vet ./...
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

# 推送前就查公开内容：仓库是公开的，推上去就公开了。有 origin/main 时连本分支的历史一起查。
gates:
	bash scripts/check-deps.sh
	@base="$$(git merge-base origin/main HEAD 2> /dev/null || true)"; \
	  PUBLIC_CONTENT_RANGE="$${base:+$$base..HEAD}" bash scripts/check-public-content.sh

# 提 PR 前的本机检查：CI 的 go 任务，加上 App 的测试（CI 在 Linux 上，不编 App）。
check: lint test gates app-test

app-test:
	cd macos && swift test

# 在 mbp64k 的测试虚拟机里跑 e2e，见 docs/agent/e2e.md。
e2e:
	bash scripts/e2e-vm.sh

# 组装菜单栏 App（ARCHITECTURE.md 6.1）：CHANNEL=debug|release；签名身份取 XDIAL_SIGN_IDENTITY。
# 只在测试虚拟机里装和跑。
CHANNEL ?= debug
app:
	bash scripts/build-app.sh $(CHANNEL)
