package main

import (
	"certmonitor/monitor"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

var (
	certmon           *monitor.Monitor
	validateParamHost *regexp.Regexp
	validateParamSNI  *regexp.Regexp
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[certmonitor] ")
	validateParamHost, _ = regexp.Compile("[A-Za-z\\d\\.\\-]*:\\d*")
	validateParamSNI, _ = regexp.Compile("[A-Za-z\\d\\.\\-]*")
	certmon = monitor.NewMonitor()

	http.HandleFunc("/ssl", onSSL)
}

func getSingleQueryParam(r *http.Request, name string) string {

	if params, ok := r.URL.Query()[name]; ok && len(params[0]) > 1 {
		return params[0]
	}

	r.ParseForm()
	if param := r.Form.Get(name); len(param) > 1 {
		return param
	}
	return ""
}

func onSSL(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodPost {

		host := getSingleQueryParam(r, "host")
		if len(host) < 1 || !validateParamHost.MatchString(host) {
			w.WriteHeader(http.StatusBadRequest)
			log.Println("Invalid request or request's parameters ", r.URL.Query())
			return
		}
		sni := getSingleQueryParam(r, "sni")
		if len(sni) < 1 || !validateParamSNI.MatchString(sni) {
			sni = ""
		}
		state := monitor.NewState(host, sni)
		certmon.UpdateState(state)
		fmt.Fprintf(w, state.ToJSON())
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
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

	certmon.Run()
	log.Println("ListenAndServe: ", certmon.Ctx.Listen)
	err := http.ListenAndServe(certmon.Ctx.Listen, nil)
	if err != nil {
		log.Fatalln("ListenAndServe:", err)
	}
}
