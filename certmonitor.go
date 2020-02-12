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

	if param := r.Form.Get(name); len(param) > 1 {
		return param
	}
	return ""
}

func onSSL(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		var resp string = ""

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
		chain := getSingleQueryParam(r, "chain")
		certs := certmon.GetCertificates(host, sni)
		if len(certs) > 0 {
			if len(chain) > 0 {
				for _, v := range certs {
					resp = resp + "\n" + monitor.X509ToJSON(v)
				}
			} else {
				resp = monitor.X509ToJSON(certs[0])
			}
		}
		fmt.Fprintf(w, resp)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func main() {

	var (
		listen  string
		timeout string
	)

	flag.StringVar(&listen, "l", "0.0.0.0:8000", "Specify listen address. Default is 0.0.0.0:8000")
	flag.StringVar(&timeout, "t", "10", "Specify connection timeout. Default is 10")
	flag.Parse()

	log.Println("ListenAndServe: ", listen)
	err := http.ListenAndServe(listen, nil)
	if err != nil {
		log.Fatalln("ListenAndServe:", err)
	}

	/*
		certmon.Timeout, err = strconv.Atoi(timeout)
		if err != nil {
			log.Printf("Set invalid timeout value - %s, will be used: 10", timeout)
			certmon.Timeout = time.Duration(10)
		}
	*/
}
