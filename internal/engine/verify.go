package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
)

// VerifyDeadline bounds Verify as a whole.
const VerifyDeadline = 2 * time.Minute

// Verification is what Verify found.
type Verification struct {
	Problems []cli.Problem
	Pending  []string
}

// Verify compiles every scenario and the whole configuration with
// placeholder secrets and checks each in a one-shot child of executable,
// ARCHITECTURE.md 3.1 and 4.1. Scenarios that compile to the same
// configuration are checked once, and one deadline bounds the whole run.
// The only error is ErrCheckUnavailable; anything about the configuration
// is a problem.
func Verify(ctx context.Context, executable string, c *config.Config) (*Verification, error) {
	ctx, cancel := context.WithTimeout(ctx, VerifyDeadline)
	defer cancel()
	v := &Verification{}
	pending := map[string]bool{}
	targets := []string{""}
	for _, s := range c.Scenarios {
		targets = append(targets, s.ID)
	}
	checked := map[string]error{}
	for _, scenario := range targets {
		result, err := Compile(c, Options{Scenario: scenario, StateDirectory: os.TempDir(), TUN: true, Stack: DefaultStack})
		if err == nil {
			key := string(result.JSON)
			cached, ok := checked[key]
			if !ok {
				cached = Check(ctx, executable, result.JSON)
				checked[key] = cached
			}
			err = cached
		}
		if errors.Is(err, ErrCheckUnavailable) {
			return nil, err
		}
		if err != nil {
			where, path := "整份配置", ""
			if scenario != "" {
				where = "场景 " + scenario
				for _, s := range c.Scenarios {
					if s.ID == scenario {
						path = s.Path
					}
				}
			}
			v.Problems = append(v.Problems, cli.Problem{
				Code: cli.CodeConfigCompile, Path: path, Message: fmt.Sprintf("%s编译后没通过 sing-box 的检查：%v", where, err),
				Hint: "检查用的是凭据占位值；如果报错指向某条线路的字段，按提示修改",
			})
			continue
		}
		for _, p := range result.Pending {
			pending[p] = true
		}
	}
	for p := range pending {
		v.Pending = append(v.Pending, p)
	}
	sort.Strings(v.Pending)
	return v, nil
}
