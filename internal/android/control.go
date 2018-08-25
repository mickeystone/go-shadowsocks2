package android

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/pkg/errors"
)

const (
	protectPath = "protect_path"
)

func DialerControl(_, _ string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		err = protectFd(int(fd))
	})
	return errors.Wrap(err, "protect_path")
}

func protectFd(fd int) error {
	conn, err := net.DialTimeout("unix", protectPath, time.Second)
	if err != nil {
		return errors.Wrap(err, "dial "+protectPath)
	}
	defer conn.Close()
	protectConn := conn.(*net.UnixConn)
	rights := syscall.UnixRights(fd)
	n, oobn, err := protectConn.WriteMsgUnix(nil, rights, nil)
	if err != nil {
		return errors.Wrap(err, "WriteMsgUnix")
	}
	if oobn != len(rights) {
		return fmt.Errorf("WriteMsgUnix got %d want %d", oobn, len(rights))
	}
	dummyByte := make([]byte, 1)
	n, err = protectConn.Read(dummyByte)
	if n == 0 || err != nil {
		return errors.Wrap(err, fmt.Sprintf("Read fd=%d", fd))
	}
	ret := dummyByte[0]
	if ret != 0 {
		return fmt.Errorf("protect_path return %d", ret)
	}
	return nil
}
