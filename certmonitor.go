package main

import (
	"certmonitor/monitor"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	certmon             *monitor.Monitor
	validateParamHost   *regexp.Regexp
	validateParamSNI    *regexp.Regexp
	validateParamNumber *regexp.Regexp
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[certmonitor] ")
	validateParamHost, _ = regexp.Compile("[A-Za-z\\d\\.\\-]*:\\d*")
	validateParamSNI, _ = regexp.Compile("[A-Za-z\\d\\.\\-]*")
	validateParamNumber, _ = regexp.Compile("\\d*")
	certmon = monitor.NewMonitor()
}

func getSingleQueryParam(r *http.Request, name string) string {

	if params, ok := r.URL.Query()[name]; ok && len(params[0]) > 0 {
		return params[0]
	}

	r.ParseForm()
	if param := r.Form.Get(name); len(param) > 0 {
		return param
	}
	return ""
}

func onCheck(w http.ResponseWriter, r *http.Request) {
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
		json.NewEncoder(w).Encode(state)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func onReport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		filter := getSingleQueryParam(r, "filter")
		if !validateParamNumber.MatchString(filter) {
			w.WriteHeader(http.StatusBadRequest)
			log.Println("Invalid request or request's parameters ", r.URL.Query())
			return
		}
		if strings.Contains(r.URL.RequestURI(), "valid") {
			value, _ := strconv.Atoi(filter)
			states := certmon.DB.GetStatesByValid(value)
			json.NewEncoder(w).Encode(states)
		} else if strings.Contains(r.URL.RequestURI(), "expire") {
			value, _ := strconv.Atoi(filter)
			certs := certmon.DB.GetCertificatesByExpire(value)
			json.NewEncoder(w).Encode(certs)
		}
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
	http.HandleFunc("/check", onCheck)
	http.HandleFunc("/report/valid", onReport)
	http.HandleFunc("/report/expire", onReport)
	log.Println("ListenAndServe: ", certmon.Ctx.Listen)
	err := http.ListenAndServe(certmon.Ctx.Listen, nil)
	if err != nil {
		log.Fatalln("ListenAndServe:", err)
	}
}
