package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/juju/gnuflag"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/internal/android"
	"github.com/shadowsocks/go-shadowsocks2/internal/fakedns"
	"github.com/shadowsocks/go-shadowsocks2/internal/plugin"
	"github.com/shadowsocks/go-shadowsocks2/internal/shadow"
	"github.com/shadowsocks/go-shadowsocks2/internal/stat"
	"github.com/shadowsocks/go-shadowsocks2/internal/stdio"
)

const (
	schemeSs = "ss"
	schemeH2 = "h2"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

var (
	isVpn bool

	aclListPath string

	timeout int

	dialer *net.Dialer

	sdcardDir string
)

var logger = log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags)

func logf(f string, v ...interface{}) {
	if config.Verbose {
		logger.Output(2, fmt.Sprintf(f, v...))
	}
}

func main() {
	runtime.GOMAXPROCS(1)

	var flags struct {
		Client   string
		Cipher   string
		Password string
		Socks    string
	}

	flag := gnuflag.NewFlagSet(os.Args[0], gnuflag.ContinueOnError)

	var bindAddr string
	var bindPort int
	var confPath string
	flag.BoolVar(&isVpn, "V", false, "vpn mode")
	flag.StringVar(&bindAddr, "b", "", "client bind address")
	flag.IntVar(&bindPort, "l", 0, "client bind port")
	flag.StringVar(&confPath, "c", "", "conf path")
	flag.StringVar(&aclListPath, "acl", "", "acl")
	flag.Bool("fast-open", false, "fast-open")
	flag.IntVar(&timeout, "t", 60, "timeout")

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.Bool("u", false, "(client-only) Enable UDP support for SOCKS")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse(false, os.Args[1:])

	dialer = &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}
	if isVpn {
		dialer.Control = android.DialerControl
		net.DefaultResolver.Dial = dialer.DialContext
		pwd, _ := os.Getwd()
		sdcardDir = "/sdcard/.shadowsocks"
		const stdoutFilename = "libss-local.log"
		if err := os.MkdirAll(sdcardDir, 0755); err != nil {
			ioutil.WriteFile(stdoutFilename, []byte(fmt.Sprintf("mkdir %s error: %v\n", sdcardDir, err)), 0644)
			os.Exit(1)
		}

		if !config.Verbose {
			if _, err := os.Stat(filepath.Join(sdcardDir, "verbose")); err == nil {
				config.Verbose = true
			}
		}

		f, _ := os.OpenFile(filepath.Join(sdcardDir, stdoutFilename), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		log.SetOutput(f)
		stdio.RedirectStream(f.Fd(), os.Stdout.Fd())
		stdio.RedirectStream(f.Fd(), os.Stderr.Fd())
		fmt.Fprintf(os.Stderr, "%v\n", os.Args)
		log.Printf("goVer: %s, now in vpn mode, pwd: %s", runtime.Version(), pwd)
	}

	if bindAddr != "" && bindPort > 0 {
		flags.Socks = fmt.Sprintf("%s:%d", bindAddr, bindPort)
	}
	if confPath != "" {
		type jsonConf struct {
			Server   string `json:"server"`
			Port     int    `json:"server_port"`
			Password string `json:"password"`
			Method   string `json:"method"`

			PluginCmd  string `json:"plugin"`
			PluginOpts string `json:"plugin_opts"`
		}
		b, err := ioutil.ReadFile(confPath)
		if err != nil {
			log.Fatalf("read %s: %v", confPath, err)
		}
		var c jsonConf
		if err := json.Unmarshal(b, &c); err != nil {
			log.Fatalf("parse json conf: %v", err)
		}
		var ssUrl *url.URL
		if strings.ToLower(c.Method) == "xchacha20-ietf-poly1305" {
			parts := strings.SplitN(c.Password, ":", 2)
			u := parts[0]
			p := ""
			if len(parts) > 1 {
				p = parts[1]
			}
			ssUrl = &url.URL{
				Scheme: schemeH2,
				User:   url.UserPassword(u, p),
			}
		} else {
			ssUrl = &url.URL{
				Scheme: schemeSs,
				User:   url.UserPassword(c.Method, c.Password),
			}
		}
		if c.PluginCmd != "" {
			plugin.LoggerFunc(logf)
			ssPlugin := plugin.NewSsPlugin(c.PluginCmd, c.PluginOpts, c.Server, c.Port)
			ssUrl.Host = ssPlugin.HostPort()
			log.Printf("plugin: %s -> %s:%d", ssUrl.Host, c.Server, c.Port)
			log.Printf("plugin: %s, opts: %s", c.PluginCmd, c.PluginOpts)
			go ssPlugin.Start()
		} else {
			ssUrl.Host = fmt.Sprintf("%s:%d", c.Server, c.Port)
		}
		if isVpn {
			fakedns.LoggerFunc(logf)
			fakedns.BaseDir(sdcardDir)
			fakedns.HostsPath([]string{"/etc/hosts", filepath.Join(sdcardDir, "hosts")})
			domain, _, _ := net.SplitHostPort(ssUrl.Host)
			fakedns.AlwaysDirectDomain(domain)
			fakedns.AclListPath(aclListPath)
			fakedns.Start()

			stat.LoggerFunc(logf)
			stat.Start()
		}
		flags.Client = ssUrl.String()
	}

	if flags.Client != "" { // client mode
		scheme := schemeSs
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.Contains(addr, "://") {
			scheme, addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		var connDial func(string, string) (net.Conn, error)
		switch scheme {
		case schemeSs:
			ciph, err := core.PickCipher(cipher, nil, password)
			if err != nil {
				log.Fatal(err)
			}
			connDial = shadow.WrapSS(addr, ciph, dialer.Dial)
		case schemeH2:
			connDial = shadow.WrapH2(addr, cipher, password, dialer.Dial)
		default:
			log.Fatalf("unsupported scheme: %s", scheme)
		}

		logf("SOCKS proxy %s <-> %s", flags.Socks, addr)
		go socksLocal(flags.Socks, connDial)
	} else {
		flag.PrintDefaults()
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func parseURL(s string) (scheme, addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	scheme = u.Scheme
	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
