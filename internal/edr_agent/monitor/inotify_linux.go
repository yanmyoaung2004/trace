//go:build linux

package monitor

import (
	"log"
	"os"
	"strconv"
	"strings"
)

func checkInotifyLimits() {
	data, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err != nil {
		return
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return
	}
	if limit < 65536 {
		log.Printf("[inotify] WARNING: max_user_watches=%d is low. Recommended >=65536", limit)
		log.Printf("[inotify]   sudo sysctl -w fs.inotify.max_user_watches=65536")
		log.Printf("[inotify]   echo fs.inotify.max_user_watches=65536 | sudo tee -a /etc/sysctl.conf")
	} else {
		log.Printf("[inotify] max_user_watches=%d", limit)
	}
}
