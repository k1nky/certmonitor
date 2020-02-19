package main

import (
	"certmonitor/monitor"
	"flag"
	"log"
	"net/http"
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
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signals
		log.Println(sig)
	}()
	certmon = monitor.NewMonitor()
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

	log.SetPrefix(certmon.Ctx.LogPrefix)
	certmon.Run()
	log.Println("ListenAndServe: ", certmon.Ctx.Listen)
	err := http.ListenAndServe(certmon.Ctx.Listen, nil)
	if err != nil {
		log.Fatalln("ListenAndServe:", err)
	}
}
