package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
)

const (
	InterfacesFlag = "ifs"
	PortFlag       = "p"
)

var (
	Log       = logrus.New()
	stop      = make(chan struct{})
	IfaceList = NewInterfaceList()

	ifs  = flag.String(InterfacesFlag, "", "Comma separated list of interfaces to watch.")
	port = flag.Int(PortFlag, 8001, "HTTP server listening port.")
)

func withLogging(f func()) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("Recovered from panic(%+v)", r)

			Log.WithField("error", err).Panicf("Stopped with panic: %s", err.Error())
		}
	}()

	f()
}

func main() {
	flag.Parse()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			Log.Infof("Signalled (%s). Shutting down.", sig)
			Log.WithField("signal", sig).Infof("Signalled. Shutting down.")
			shutdown(0)
		}
	}()

	splitIfs := strings.Split(*ifs, ",")
	if *ifs == "" || len(splitIfs) == 0 {
		Log.Infof("At least one interface to watch must be provided via the -%s command line argument.", InterfacesFlag)
		os.Exit(1)
	}

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		Log.WithField("error", err).Fatalf("Error getting the list of interfaces.")
	}

	sort.Strings(splitIfs)

	var wg sync.WaitGroup
	iCount := 0
	for _, iface := range ifaces {
		i := sort.SearchStrings(splitIfs, iface.Name)

		if i < len(splitIfs) && splitIfs[i] == iface.Name {
			wg.Add(1)
			iCount++
			// Start up a watch on each interface.
			go func(iface net.Interface) {
				defer wg.Done()
				if err := watch(iface); err != nil {
					Log.WithFields(logrus.Fields{
						"error":     err,
						"interface": iface.Name,
					}).Errorf("Error watching interface.")
				}
			}(iface)
		}
	}

	if iCount == 0 {
		Log.Infof("Exited. No valid interfaces provided.")
		os.Exit(1)
	}

	go func() {
		if err = <-StartHTTPServer(*port); err != nil {
			Log.WithField("error", err).Fatal("Error starting HTTP server.")
		}
	}()

	wg.Wait()

	Log.Infof("Exited.")
}

func shutdown(code int) {
	Log.WithField("code", code).Infof("Stopping.")

	close(stop)
}
