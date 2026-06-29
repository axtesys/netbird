package version

import (
	"golang.org/x/sys/windows/registry"
	"runtime"
)

const (
	// AXTESYS CHANGE: axtesys pkg host, normalized os/arch names.
	urlWinExe    = "https://netbird.axtesys.it/pkgs/windows/amd64"
	urlWinExeArm = "https://netbird.axtesys.it/pkgs/windows/arm64"
)

var regKeyAppPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Netbird"

// DownloadUrl return with the proper download link
func DownloadUrl() string {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyAppPath, registry.QUERY_VALUE)
	if err != nil {
		return downloadURL
	}

	url := urlWinExe
	if runtime.GOARCH == "arm64" {
		url = urlWinExeArm
	}

	return url
}
