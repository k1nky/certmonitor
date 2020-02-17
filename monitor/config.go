package monitor

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type ZoneConfig struct {
	Name   string `json:"name"`
	Master string `json:"master"`
	Proto  string `json:"proto,omitempty"`
}

type StateConfig struct {
	Host string `json:"host"`
	SNI  string `json:"sni"`
}

type Context struct {
	Listen          string        `json:"listen"`
	TLSTimeout      int           `json:"tlsTimeout"`
	RetransferDelay int           `json:"retransferDelay"`
	WatcherDelay    int           `json:"watcherDelay"`
	Zones           []ZoneConfig  `json:"zones"`
	Data            string        `json:"data"`
	MaxThreads      int           `json:"maxThreads"`
	States          []StateConfig `json:"states"`
}

func loadConfig(filename string) (*Context, error) {
	var ctx *Context

	file, err := os.Open(filename)
	if err != nil {
		log.Println("LoadConfig: ", err)
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("LoadConfig: ", err)
		return nil, err
	}

	if err := json.Unmarshal(bytes, &ctx); err != nil {
		log.Println("LoadConfig: ", err)
		return nil, err
	}
	return ctx, nil
}
