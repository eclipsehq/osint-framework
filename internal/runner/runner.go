package runner

import (
	"context"
	"sync"
	"time"

	"github.com/osintfw/osint/pkg/types"
)

type Task struct {
	Name string
	Fn   func(ctx context.Context) types.ModuleResult
}

type Runner struct {
	workers int
	timeout time.Duration
}

func New(workers int, timeout time.Duration) *Runner {
	if workers <= 0 {
		workers = 5
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Runner{workers: workers, timeout: timeout}
}

func (r *Runner) Run(ctx context.Context, tasks []Task) []types.ModuleResult {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var wg sync.WaitGroup
	taskCh := make(chan Task, len(tasks))
	resultCh := make(chan types.ModuleResult, len(tasks))

	for i := 0; i < r.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				select {
				case <-ctx.Done():
					resultCh <- types.ModuleResult{
						Module:    task.Name,
						Timestamp: time.Now(),
						Error:     ctx.Err(),
					}
					return
				default:
					res := task.Fn(ctx)
					if res.Timestamp.IsZero() {
						res.Timestamp = time.Now()
					}
					resultCh <- res
				}
			}
		}()
	}

	go func() {
		for _, t := range tasks {
			taskCh <- t
		}
		close(taskCh)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []types.ModuleResult
	for res := range resultCh {
		results = append(results, res)
	}

	return results
}
