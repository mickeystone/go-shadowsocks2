// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// copy from net/hosts.go with some modifications.

package fakedns

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// hosts contains known host entries.
var hosts struct {
	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byName map[string][]string
}

var hostsPaths = []string{"/etc/hosts"}

func HostsPath(paths []string) {
	hostsPaths = paths
}

func readHosts() {
	for _, path := range hostsPaths {
		if err := readHostsFromFile(path); err != nil && !os.IsNotExist(err) {
			logf("readHosts from %s error: %v", path, err)
		}
	}
	logf("readHosts %d items", len(hosts.byName))
}

func readHostsFromFile(path string) error {
	if hosts.byName == nil {
		hosts.byName = make(map[string][]string)
	}
	hs := hosts.byName

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if ip := net.ParseIP(f[0]); ip == nil {
			continue
		}
		addr := f[0]
		for i := 1; i < len(f); i++ {
			h := []byte(f[i])
			lowerASCIIBytes(h)
			key := absDomainName(h)
			hs[key] = append(hs[key], addr)
		}
	}
	// Update the data cache.
	return nil
}

// lookupStaticHost looks up the addresses for the given host from /etc/hosts.
func lookupStaticHost(host string) []string {
	if len(hosts.byName) != 0 {
		// TODO(jbd,bradfitz): avoid this alloc if host is already all lowercase?
		// or linear scan the byName map if it's small enough?
		lowerHost := []byte(host)
		lowerASCIIBytes(lowerHost)
		if ips, ok := hosts.byName[absDomainName(lowerHost)]; ok {
			ipsCp := make([]string, len(ips))
			copy(ipsCp, ips)
			return ipsCp
		}
	}
	return nil
}

func absDomainName(b []byte) string {
	hasDots := false
	for _, x := range b {
		if x == '.' {
			hasDots = true
			break
		}
	}
	if hasDots && b[len(b)-1] != '.' {
		b = append(b, '.')
	}
	return string(b)
}

func lowerASCIIBytes(x []byte) {
	for i, b := range x {
		if 'A' <= b && b <= 'Z' {
			x[i] += 'a' - 'A'
		}
	}
}
