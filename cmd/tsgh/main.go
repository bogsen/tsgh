package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tailscale.com/tsnet"

	"tsgh/internal/broker"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	config, err := broker.LoadConfig()
	if err != nil {
		return err
	}
	tailnet := &tsnet.Server{
		Hostname: config.Hostname,
		Dir:      config.TSNetDir(),
	}
	defer tailnet.Close()
	status, err := tailnet.Up(context.Background())
	if err != nil {
		return fmt.Errorf("start tsnet: %w", err)
	}
	if len(status.CertDomains) == 0 {
		return errors.New("tsnet HTTPS is not enabled")
	}
	local, err := tailnet.LocalClient()
	if err != nil {
		return fmt.Errorf("start tsnet: %w", err)
	}
	app, err := broker.NewApp(broker.AppConfig{
		RedirectURI: "https://" + status.CertDomains[0] + "/auth/github/callback",
		WhoIs:       local.WhoIs,
		GitHub:      config.GitHub,
		Store:       config.Store,
		Logf:        log.Printf,
	})
	if err != nil {
		return err
	}
	httpListener, err := tailnet.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("listen on tailnet HTTP: %w", err)
	}
	httpsListener, err := tailnet.ListenTLS("tcp", ":443")
	if err != nil {
		httpListener.Close()
		return fmt.Errorf("listen on tailnet HTTPS: %w", err)
	}

	servers := []*http.Server{
		newHTTPServer(app),
		newHTTPServer(app),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	revokerDone := make(chan struct{})
	go func() {
		app.RunRevoker(ctx)
		close(revokerDone)
	}()
	errorsSeen := make(chan error, len(servers))
	go serve(errorsSeen, servers[0], httpListener)
	go serve(errorsSeen, servers[1], httpsListener)
	log.Printf("tsgh listening on http://%s:80 and https://%s:443", config.Hostname, config.Hostname)

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errorsSeen:
		stop()
		if serveErr != nil {
			log.Printf("server stopped unexpectedly: %v", serveErr)
		}
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	select {
	case <-revokerDone:
	case <-shutdownCtx.Done():
		log.Printf("revoker shutdown timed out; pending records will be retried after restart")
	}
	if serveErr != nil {
		return serveErr
	}
	return nil
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       time.Minute,
	}
}

func serve(result chan<- error, server *http.Server, listener net.Listener) {
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	result <- err
}
