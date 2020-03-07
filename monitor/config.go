package monitor

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

// ZoneConfig represents item at `zone` configuration section
// 	Master - master DNS server
//	Name - zone name
//	Proto - protocol (tcp/udp)
type ZoneConfig struct {
	Master   string   `json:"master"`
	Name     string   `json:"name"`
	Proto    string   `json:"proto,omitempty"`
	OmitMx   bool     `json:"omitMX"`
	PortMX   int      `json:"portMX"`
	Excludes []string `json:"excludes"`
}

// Config represents application configuration
//	WorkDir - path, contains db, etc
//	Listen - listen interface and port
//	LogPrefix - global logging prefix
//	MaxThreads - max number of monitor workers
//	RetransferDelay - delay between afxr requests
//	TLSTimeout - timeout TLS connections
//	WatcherDelay - delay between periodic state checks
// Zones - see `ZoneConfig`
type Config struct {
	WorkDir         string       `json:"workDir"`
	Listen          string       `json:"listen"`
	LogPrefix       string       `json:"logPrefix"`
	MaxThreads      int          `json:"maxThreads"`
	RetransferDelay int          `json:"retransferDelay"`
	TLSTimeout      int          `json:"tlsTimeout"`
	WatcherDelay    int          `json:"watcherDelay"`
	Zones           []ZoneConfig `json:"zones"`
}

func loadConfig(filename string) (*Config, error) {
	var cfg *Config

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

	if err := json.Unmarshal(bytes, &cfg); err != nil {
		log.Println("LoadConfig: ", err)
		return nil, err
	}
	return cfg, nil
}
