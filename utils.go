package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"
)

const (
	minKernelVer = "4.8.0"
	maxKernelVer = "5.8.0"
)

var (
	isMinKernelVer = MustCompile(">=" + minKernelVer)
	isMaxKernelVer = MustCompile(">=" + maxKernelVer)
)

// MustCompile wraps go-version.NewConstraint, panicing when an error is
// returns (this occurs when the constraint cannot be parsed).
// It is intended to be use similar to re.MustCompile, to ensure unparseable
// constraints are caught in testing.
func MustCompile(constraint string) semver.Range {
	verCheck, err := Compile(constraint)
	if err != nil {
		panic(fmt.Errorf("cannot compile go-version constraint '%s' %s", constraint, err))
	}
	return verCheck
}

// Compile trivially wraps go-version.NewConstraint, returning the constraint
// and error
func Compile(constraint string) (semver.Range, error) {
	return semver.ParseRange(constraint)
}

// MustVersion wraps go-version.NewVersion, panicing when an error is
// returns (this occurs when the version cannot be parsed).
func MustVersion(version string) semver.Version {
	ver, err := Version(version)
	if err != nil {
		panic(fmt.Errorf("cannot compile go-version version '%s' %s", version, err))
	}
	return ver
}

// Version wraps go-version.NewVersion, panicing when an error is
// returns (this occurs when the version cannot be parsed).
func Version(version string) (semver.Version, error) {
	ver, err := semver.ParseTolerant(version)
	if err != nil {
		return ver, err
	}

	if len(ver.Pre) == 0 {
		return ver, nil
	}

	for _, pre := range ver.Pre {
		if strings.Contains(pre.VersionStr, "rc") ||
			strings.Contains(pre.VersionStr, "beta") ||
			strings.Contains(pre.VersionStr, "alpha") ||
			strings.Contains(pre.VersionStr, "snapshot") {
			return ver, nil
		}
	}

	strSegments := make([]string, 3)
	strSegments[0] = strconv.Itoa(int(ver.Major))
	strSegments[1] = strconv.Itoa(int(ver.Minor))
	strSegments[2] = strconv.Itoa(int(ver.Patch))
	verStr := strings.Join(strSegments, ".")
	return semver.ParseTolerant(verStr)
}

func parseKernelVersion(ver string) (semver.Version, error) {
	verStrs := strings.Split(ver, ".")
	switch {
	case len(verStrs) < 2:
		return semver.Version{}, fmt.Errorf("unable to get kernel version from %q", ver)
	case len(verStrs) < 3:
		verStrs = append(verStrs, "0")
	}
	// We are assuming the kernel version will be something as:
	// 4.9.17-040917-generic

	// If verStrs is []string{ "4", "9", "17-040917-generic" }
	// then we need to retrieve patch number.
	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[2])
	if patch == "" {
		verStrs[2] = "0"
	} else {
		verStrs[2] = patch
	}
	return Version(strings.Join(verStrs[:3], "."))
}

// GetKernelVersion returns the version of the Linux kernel running on this host.
func GetKernelVersion() (semver.Version, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return semver.Version{}, err
	}
	return parseKernelVersion(string(unameBuf.Release[:]))
}
