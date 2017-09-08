package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const (
	realUpstreamDns = "114.114.114.114:53"

	defaultUDPSize = 1460

	dnsTimeout time.Duration = 2 * time.Second
)

var (
	fakeDnsMapping      = make(map[string]string)
	fakeDnsMappingMutex sync.RWMutex

	fakeDnsIp4 uint32 = 184549376 // 11.0.0.0
)

type dnsRule interface {
	Match(domain string) bool
}

func NewDnsDomainSuffixRule(rule string) *dnsDomainSuffixRule {
	if len(rule) == 0 {
		return nil
	}
	if rule[0] != '.' {
		rule = "." + rule
	}
	return &dnsDomainSuffixRule{
		rule: rule,
	}
}

type dnsDomainSuffixRule struct {
	rule string
}

func (r *dnsDomainSuffixRule) Match(domain string) bool {
	if r == nil {
		return false
	}
	if domain == r.rule[1:] {
		return true
	}
	if strings.HasSuffix(domain, r.rule) {
		return true
	}
	return false
}

func NewDnsDomainRegExpRule(rule string) *dnsDomainRegExpRule {
	exp, err := regexp.Compile(rule)
	if err != nil {
		return nil
	}
	return &dnsDomainRegExpRule{
		rule: exp,
	}
}

type dnsDomainRegExpRule struct {
	rule *regexp.Regexp
}

func (r *dnsDomainRegExpRule) Match(domain string) bool {
	if r == nil {
		return false
	}
	return r.rule.MatchString(domain)
}

func fakeDns(port int) {
	const specialRegExpPrefix = `(^|\.)`
	const specialRegExpPrefixLen = len(specialRegExpPrefix)
	var rules []dnsRule
	f, err := os.Open("custom-rules.acl")
	if err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "[") {
				continue
			}
			if _, _, err := net.ParseCIDR(line); err == nil {
				continue
			}
			var rule dnsRule
			if strings.HasSuffix(line, "$") && strings.HasPrefix(line, specialRegExpPrefix) {
				line = line[specialRegExpPrefixLen : len(line)-1]
				rule = NewDnsDomainSuffixRule(strings.Replace(line, `\.`, ".", -1))
			} else {
				rule = NewDnsDomainRegExpRule(line)
			}
			if rule != nil {
				rules = append(rules, rule)
			}
		}
		f.Close()
	}
	logf("loaded %d rules", len(rules))
	srv := dns.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		Net:  "udp4",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ok := false
			var q dns.Question
			for i := range r.Question {
				if r.Question[i].Qtype != dns.TypeAAAA {
					q = r.Question[i]
					ok = true
				}
			}
			logf("dns query: %#v", q)
			if !ok {
				dns.HandleFailed(w, r)
				return
			}
			if q.Qtype == dns.TypeA && strings.Count(q.Name, ".") > 1 {
				var ip string
				fakeDnsMappingMutex.RLock()
				ip, ok := fakeDnsMapping[q.Name]
				fakeDnsMappingMutex.RUnlock()
				if !ok {
					shouldFake := false
					name := q.Name
					nameLen := len(name)
					if name[nameLen-1] == '.' {
						name = name[:nameLen-1]
					}
					for _, rule := range rules {
						if rule.Match(name) {
							shouldFake = true
							break
						}
					}
					if shouldFake {
						newIpInt := atomic.AddUint32(&fakeDnsIp4, 1)
						newIpBytes := make([]byte, net.IPv4len)
						binary.BigEndian.PutUint32(newIpBytes, newIpInt)
						ip = net.IP(newIpBytes).String()
					}
					fakeDnsMappingMutex.Lock()
					if ip != "" {
						fakeDnsMapping[ip] = name
					}
					fakeDnsMapping[q.Name] = ip
					fakeDnsMappingMutex.Unlock()
					logf("fakeDns insert: %s -> %s", q.Name, ip)
				}
				if ip != "" {
					m := new(dns.Msg)
					m.Id = r.Id
					m.Response = true
					m.Opcode = dns.OpcodeQuery
					m.CheckingDisabled = true
					m.Rcode = dns.RcodeSuccess
					m.Question = []dns.Question{q}
					m.Answer = []dns.RR{&dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: q.Qtype,
							Ttl:    1,
							Class:  dns.ClassINET,
						},
						A: net.ParseIP(ip),
					}}
					w.WriteMsg(m)
					return
				}
			}
			// 普通的exchange
			co := new(dns.Conn)
			co.UDPSize = defaultUDPSize
			if co.Conn, err = net.DialTimeout("udp", realUpstreamDns, dnsTimeout); err == nil {
				defer co.Close()
				co.SetWriteDeadline(time.Now().Add(dnsTimeout))
				if err = co.WriteMsg(r); err == nil {
					co.SetReadDeadline(time.Now().Add(dnsTimeout))
					resp, err := co.ReadMsg()
					if err == nil {
						w.WriteMsg(resp)
						return
					}
				}
			}
			dns.HandleFailed(w, r)
		}),
		UDPSize: defaultUDPSize,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("dns listen: %v", err)
	}
}

func fakeDnsReplace(orig socks.Addr) socks.Addr {
	ip, port, _ := net.SplitHostPort(orig.String())
	if net.ParseIP(ip) == nil {
		return orig
	}
	fakeDnsMappingMutex.RLock()
	domain := fakeDnsMapping[ip]
	fakeDnsMappingMutex.RUnlock()
	if domain == "" {
		return orig
	}
	addr := socks.ParseAddr(net.JoinHostPort(domain, port))
	if addr == nil {
		return orig
	}
	logf("fakeDns replace: %s -> %s", orig, addr)
	return addr
}
