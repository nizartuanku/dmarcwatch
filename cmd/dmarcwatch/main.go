// dmarcwatch is the DmarcWatch product binary: DMARC aggregate-report (RUA)
// monitoring on Sentinel Core.
//
//	dmarcwatch                    # dashboard on 127.0.0.1:8429
//	dmarcwatch -webhook <url>     # push new findings to a webhook
//
// Add an email domain, upload the DMARC aggregate reports you receive (.xml,
// .xml.gz, or .zip), and DmarcWatch shows who sends mail as your domain, flags
// suspected spoofing and unexpected new senders, and tells you when you are
// ready to tighten the policy from p=none toward p=reject.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/dmarcwatch/dmarcwatch"
	"github.com/nizartuanku/dmarcwatch/license"
	"github.com/nizartuanku/dmarcwatch/notify"
	"github.com/nizartuanku/dmarcwatch/sched"
	"github.com/nizartuanku/dmarcwatch/store"
	"github.com/nizartuanku/dmarcwatch/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// dmarcwatchTierLimits: free = 1 domain, Pro = 10, Team = unlimited.
var dmarcwatchTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 1, RetentionDays: 30, Channels: []string{"webhook", "syslog"}},
	license.TierPro: {MaxTargets: 10, RetentionDays: 365,
		Channels: []string{"webhook", "syslog", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "syslog", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8429", "dashboard listen address")
	dbPath := flag.String("db", "dmarcwatch.db", "SQLite database path")
	licFile := flag.String("license", "dmarcwatch-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
	syslogAddr := flag.String("syslog", "", "syslog collector host:port for findings, e.g. 127.0.0.1:5514 (point this at Loglight to correlate across products)")
	syslogNet := flag.String("syslog-network", "udp", "syslog transport: udp or tcp")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	repStore, err := dmarcwatch.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	module := dmarcwatch.New(repStore)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}
	modID := module.Describe().ID

	// Restore saved domains before Start so each re-checks on boot.
	if saved, err := st.ListSavedTargets(modID); err == nil {
		for _, raw := range saved {
			if _, err := scheduler.AddTarget(modID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "dmarcwatch: skipping saved domain %q: %v\n", raw, err)
			}
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)
	server.Targets = st
	server.TierLimits = dmarcwatchTierLimits

	console := &dmarcwatch.Console{
		Store: repStore,
		Domains: func() []string {
			ts := scheduler.ListTargets(modID)
			out := make([]string, 0, len(ts))
			for _, t := range ts {
				out = append(out, t.Canonical)
			}
			return out
		},
		OnIngest: func(domains []string) {
			// A fresh upload should show findings immediately, whatever the
			// tier — this is ingestion follow-through, not an on-demand scan.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				_ = scheduler.ScanNow(ctx, modID)
			}()
		},
	}
	server.ExtraRoutes = console.Register

	var channels []notify.Channel
	if *webhook != "" {
		channels = append(channels, &notify.WebhookChannel{URL: *webhook})
	}
	if *syslogAddr != "" {
		channels = append(channels, &notify.SyslogChannel{Addr: *syslogAddr, Network: *syslogNet})
	}
	if len(channels) > 0 {
		disp := notify.NewDispatcher(notify.Config{}, channels...)
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("DmarcWatch %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "dmarcwatch: "+msg)
	os.Exit(1)
}
