package interfaces

import (
	"context"
	"github.com/osintfw/osint/pkg/types"
)

type Module interface {
	Name() string
	Run(ctx context.Context, target string) types.ModuleResult
}
