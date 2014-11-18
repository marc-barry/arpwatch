package main

import (
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
)

var (
	Log  = logrus.New()
	stop = make(chan struct{})
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			Log.Infof("Signalled (%s). Shutting down.", sig)
			Log.WithField("signal", sig).Infof("Signalled. Shutting down.")
			shutdown(0)
		}
	}()

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		Log.WithField("error", err).Fatalf("Error getting the list of interfaces.")
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a watch on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := watch(&iface); err != nil {
				Log.WithFields(logrus.Fields{
					"error":     err,
					"interface": iface.Name,
				}).Errorf("Error watching interface.")
			}
		}(iface)
	}

	wg.Wait()

	Log.Infof("Exited.")
}

func shutdown(code int) {
	Log.WithField("code", code).Infof("Stopping.")

	close(stop)
}
