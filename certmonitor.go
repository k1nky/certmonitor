package main

import (
	"certmonitor/monitor"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	certmon *monitor.Monitor
	signals chan os.Signal
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	catchOSSignals()
	certmon = monitor.NewMonitor()
}

func catchOSSignals() {
	signals = make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR2)
	go func() {
		for {
			sig := <-signals
			if sig == syscall.SIGUSR2 {
				certmon.LoadConfig(certmon.ConfigFile)
			} else {
				certmon.Stop()
				stopHTTPServer()
				return
			}
		}
	}()
}

func main() {

	var (
		filename string
	)

	flag.StringVar(&filename, "f", "certmonitor.json", "Specify configuration file. Default is certmon.json")
	flag.Parse()

	if err := certmon.LoadConfig(filename); err != nil {
		return
	}

	log.SetPrefix(certmon.Cfg.LogPrefix)
	certmon.Run()
	runHTTPServer()
}
