package main

import (
	"certmonitor/monitor"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

var (
	validateParamHost   *regexp.Regexp
	validateParamSNI    *regexp.Regexp
	validateParamNumber *regexp.Regexp
	httpSrv             *http.Server
	httpMux             *http.ServeMux
)

func init() {
	validateParamHost, _ = regexp.Compile("[A-Za-z\\d\\.\\-]{1,}:\\d{2,}")
	validateParamSNI, _ = regexp.Compile("[A-Za-z\\d\\.\\-]{1,}")
	validateParamNumber, _ = regexp.Compile("\\d*")

	httpMux = &http.ServeMux{}
	httpMux.HandleFunc("/check", onCheck)
	httpMux.HandleFunc("/certs", onCerts)
	httpMux.HandleFunc("/states", onStates)
	httpMux.HandleFunc("/statecerts", onStateCerts)
	fs := http.FileServer(http.Dir("ui"))
	httpMux.Handle("/", fs)
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
		if !validateParamHost.MatchString(host) {
			replyBadRequest(w, r)
			return
		}
		sni := getSingleQueryParam(r, "sni")
		if !validateParamSNI.MatchString(sni) {
			sni = ""
		}
		state := monitor.NewState(host, sni)
		certmon.UpdateState(state)
		json.NewEncoder(w).Encode(state)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func onCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		id := getSingleQueryParam(r, "id")
		expire := getSingleQueryParam(r, "expire")
		if !validateParamNumber.MatchString(id) || !validateParamNumber.MatchString(expire) {
			replyBadRequest(w, r)
			return
		}
		if len(id) != 0 {
			value, _ := strconv.Atoi(id)
			cert := certmon.DB.GetCertificateByID(value)
			json.NewEncoder(w).Encode(cert)
			return
		}
		if len(expire) != 0 {
			value, _ := strconv.Atoi(expire)
			certs := certmon.DB.GetCertificatesByExpire(value)
			json.NewEncoder(w).Encode(certs)
			return
		}

		certs := certmon.DB.GetCertificatesBy("")
		json.NewEncoder(w).Encode(certs)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func onStates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		id := getSingleQueryParam(r, "id")
		valid := getSingleQueryParam(r, "valid")
		if !validateParamNumber.MatchString(id) || !validateParamNumber.MatchString(valid) {
			replyBadRequest(w, r)
			return
		}
		if len(id) != 0 {
			value, _ := strconv.Atoi(id)
			state := certmon.DB.GetStateByID(value)
			json.NewEncoder(w).Encode(state)
			return
		}
		if len(valid) != 0 {
			value, _ := strconv.Atoi(valid)
			states := certmon.DB.GetStatesByValid(value)
			json.NewEncoder(w).Encode(states)
			return
		}
		states := certmon.DB.GetStatesBy("")
		json.NewEncoder(w).Encode(states)
	} else if r.Method == http.MethodPost {
		host := getSingleQueryParam(r, "host")
		if !validateParamHost.MatchString(host) {
			replyBadRequest(w, r)
			return
		}
		sni := getSingleQueryParam(r, "sni")
		if !validateParamSNI.MatchString(sni) {
			sni = ""
		}
		state := monitor.NewState(host, sni)
		state.Type = monitor.CustomState
		if err := certmon.DB.InsertState(*state); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func onStateCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		expire := getSingleQueryParam(r, "expire")
		if !validateParamNumber.MatchString(expire) {
			replyBadRequest(w, r)
			return
		}
		if value, err := strconv.Atoi(expire); err != nil {
			states := certmon.DB.GetStateCertsBy("")
			json.NewEncoder(w).Encode(states)
		} else {
			states := certmon.DB.GetStatesByExpire(value)
			json.NewEncoder(w).Encode(states)
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func replyBadRequest(w http.ResponseWriter, r *http.Request) {
	log.Println("Invalid request or request's parameters ", r.URL.Query())
	w.WriteHeader(http.StatusBadRequest)
}

func runHTTPServer() {
	httpSrv = &http.Server{
		Addr:         certmon.Cfg.Listen,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      httpMux,
	}

	log.Println("ListenAndServe: ", certmon.Cfg.Listen)
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Println("ListenAndServe:", err)
	}

}

func stopHTTPServer() {
	httpSrv.Close()
}
