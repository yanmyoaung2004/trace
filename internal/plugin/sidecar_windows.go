package plugin

import (
	"os"
)

type osSignal = os.Signal

var execCmdStop os.Signal

func init() {
	_ = os.Kill
}
