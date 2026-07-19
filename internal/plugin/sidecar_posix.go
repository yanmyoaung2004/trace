// +build !windows

package plugin

import (
	"os"
	"syscall"
)

type osSignal = os.Signal

var execCmdStop = syscall.SIGTERM

func init() {
	_ = os.Kill
}
