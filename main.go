package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/docker/docker/pkg/archive"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

//go:embed "rootfs.tar.gz"
var rootfs []byte

//Embed config.json too
//go:embed "config.json"
var configjson []byte

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			logrus.Fatal(err)
		}
		panic("--this line should have never been executed, congratulations--")
	}
}

func main() {

	rootFsTmp, err := ioutil.TempDir("", "rootfs")
	if err != nil {
		logrus.Error(err)
		return
	}

	logrus.Infof("Extracting to %s...", rootFsTmp)

	stateTmp, err := ioutil.TempDir("", "containerstate")
	if err != nil {
		logrus.Error(err)
		return
	}

	defer func() {
		logrus.Infof("Removing extracted files from %s...", rootFsTmp)
		// Remove the rootfs after the container has exited.
		if err := os.RemoveAll(rootFsTmp); err != nil {
			logrus.Warnf("removing rootfs failed: %v", err)
		}
		if err := os.RemoveAll(stateTmp); err != nil {
			logrus.Warnf("removing container state failed: %v", err)
		}
	}()

	// Unpack the tarball.
	r := bytes.NewReader(rootfs)
	if err := archive.Untar(r, rootFsTmp, &archive.TarOptions{NoLchown: true}); err != nil {
		logrus.Error(err)
		return
	}

	logrus.Infof("Copying resolv.conf...")
	resolvConf, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		logrus.Error(err)
		return
	}

	// Write a resolv.conf.
	if err := ioutil.WriteFile(filepath.Join(rootFsTmp, "etc", "resolv.conf"), resolvConf, 0755); err != nil {
		logrus.Error(err)
		return
	}

	logrus.Infof("Executing...")
	factory, err := libcontainer.New(stateTmp, libcontainer.RootlessCgroupfs, libcontainer.InitArgs(os.Args[0], "init"))
	if err != nil {
		logrus.Error(err)
		return
	}

	defaultMountFlags := unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV

	var devs []*devices.Rule
	for _, device := range specconv.AllowedDevices {
		devs = append(devs, &device.Rule)
	}

	u, err := user.Current()
	if err != nil {
		logrus.Error(err)
		return
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	logrus.Infof("Current user UID %d GID %d", uid, gid)

	var processConfig struct {
		Process struct {
			Args []string
			Env  []string
			Cwd  string
		}
	}
	if err := json.Unmarshal(configjson, &processConfig); err != nil {
		logrus.Error(err)
		return
	}

	mounts := []*configs.Mount{

		{
			Source:      "/",
			Destination: "/host",
			Device:      "bind",
			Flags:       unix.MS_BIND | unix.MS_REC,
		},
		{
			Source:      "proc",
			Destination: "/proc",
			Device:      "proc",
			Flags:       defaultMountFlags,
		},
		{
			Source:      "tmpfs",
			Destination: "/dev",
			Device:      "tmpfs",
			Flags:       unix.MS_NOSUID | unix.MS_STRICTATIME,
			Data:        "mode=755",
		},
		{
			Source:      "devpts",
			Destination: "/dev/pts",
			Device:      "devpts",
			Flags:       unix.MS_NOSUID | unix.MS_NOEXEC,
			Data:        "newinstance,ptmxmode=0666,mode=0620",
		},
		{
			Device:      "tmpfs",
			Source:      "shm",
			Destination: "/dev/shm",
			Data:        "mode=1777,size=65536k",
			Flags:       defaultMountFlags,
		},
	}

	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		mounts = append(mounts, &configs.Mount{
			Source:      "/var/run/docker.sock",
			Destination: "/var/run/docker.sock",
			Device:      "bind",
			Flags:       unix.MS_BIND | unix.MS_REC,
		})
	}

	config := &configs.Config{
		RootlessEUID:    uid != 0,
		RootlessCgroups: true,
		Rootfs:          rootFsTmp,
		Capabilities: &configs.Capabilities{
			Bounding: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Effective: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Inheritable: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Permitted: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Ambient: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
		},
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
			{Type: configs.NEWUSER},
			{Type: configs.NEWCGROUP},
		}),
		Cgroups: &configs.Cgroup{
			Name:   "ctrwrap",
			Parent: "system",
			Resources: &configs.Resources{
				Devices: []*devices.Rule{
					{
						Type:  'a',
						Allow: true,
					},
				},
			},
		},
		MaskPaths: []string{
			"/proc/kcore",
			"/sys/firmware",
		},
		ReadonlyPaths: []string{
			"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
		},
		Devices:  specconv.AllowedDevices,
		Hostname: "ctrwrap",
		Mounts:   mounts,
		Rlimits: []configs.Rlimit{
			{
				Type: unix.RLIMIT_NOFILE,
				Hard: uint64(1025),
				Soft: uint64(1025),
			},
		},
	}

	if uid == 0 {
		config.UidMappings = []configs.IDMap{
			{
				ContainerID: 0,
				HostID:      0,
				Size:        65536,
			},
		}
		config.GidMappings = []configs.IDMap{
			{
				ContainerID: 0,
				HostID:      0,
				Size:        65536,
			},
		}
	} else {
		config.UidMappings = []configs.IDMap{
			{
				ContainerID: 0,
				HostID:      uid,
				Size:        1,
			},
		}
		config.GidMappings = []configs.IDMap{
			{
				ContainerID: 0,
				HostID:      gid,
				Size:        1,
			},
		}
	}

	//TODO: Random ID
	container, err := factory.Create("ctrwrap", config)
	defer func() {
		if container != nil {
			container.Destroy()
		}
	}()

	if err != nil {
		logrus.Error(err)
		return
	}

	args := append(processConfig.Process.Args, os.Args[1:]...)
	logrus.Infof("Args: %v", args)

	process := &libcontainer.Process{
		Args:   args,
		Env:    append(processConfig.Process.Env, os.Environ()...),
		Cwd:    processConfig.Process.Cwd,
		User:   "0",
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Init:   true,
	}

	err = container.Run(process)
	if err != nil {
		logrus.Error(err)
		return
	}

	// wait for the process to finish.
	_, err = process.Wait()
	if err != nil {
		logrus.Error(err)
		return
	}
}
