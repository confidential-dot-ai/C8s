//go:build linux

package ruleset

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The bpf commands and link types this package reads, from bpf.h. Link IDs are
// global, so walking them needs CAP_BPF in the initial user namespace, which
// the enforcer holds.
const (
	bpfObjGetInfoByFD = 15
	bpfProgQuery      = 16
	bpfLinkGetFDByID  = 30
	bpfLinkGetNextID  = 31

	bpfLinkTypeNetNS     = 5
	bpfLinkTypeNetfilter = 10
)

// The attach types a packet hook is queried by, from bpf.h: the tcx hooks of
// any interface and the netkit hooks of a netkit one.
const (
	bpfTcxIngress    = 46
	bpfTcxEgress     = 47
	bpfNetkitPrimary = 54
	bpfNetkitPeer    = 55
)

// enumerateBPFLinks is a var so tests can drive link decisions without CAP_BPF.
var enumerateBPFLinks = liveBPFLinks

// queryHookPrograms is a var so tests can drive hook decisions without CAP_BPF.
var queryHookPrograms = liveHookPrograms

// bpfLink is one BPF link as the kernel describes it.
type bpfLink struct {
	linkType uint32
	// target is the first field of the link type's info union: the namespace
	// inode a netns link is matched by.
	target uint32
}

// bpfLinkInfo is the head of bpf_link_info: the fields before its union, the
// alignment hole, and the union's first field.
type bpfLinkInfo struct {
	LinkType uint32
	ID       uint32
	ProgID   uint32
	Padding  uint32
	Target   uint32
}

// bpfLinkInfoSize is what the kernel is asked to fill. The unused constant
// pins the union's offset: a shorter head makes it negative and fails to
// compile.
const (
	bpfLinkInfoSize = int(unsafe.Sizeof(bpfLinkInfo{}))
	_               = uint(unsafe.Offsetof(bpfLinkInfo{}.Target) - 16)
)

// bpfQueryAttr is the attribute of BPF_PROG_QUERY: the interface and hook
// asked about, with no room for program IDs, so the kernel answers only their
// count. The buffer spans the struct through v6.18's revision, which the
// kernel writes back by fixed offset: a shorter one is written past.
type bpfQueryAttr struct {
	target             uint32
	attachType         uint32
	queryFlags         uint32
	attachFlags        uint32
	programIDs         uint64
	count              uint32
	_                  uint32
	programAttachFlags uint64
	linkIDs            uint64
	linkAttachFlags    uint64
	revision           uint64
}

// The kernel's write-back offsets and the buffer width, pinned at compile
// time the same way bpfLinkInfo pins its union's offset.
const (
	_ = uint(unsafe.Offsetof(bpfQueryAttr{}.attachFlags) - 12)
	_ = uint(unsafe.Offsetof(bpfQueryAttr{}.count) - 24)
	_ = uint(unsafe.Offsetof(bpfQueryAttr{}.revision) - 56)
	_ = uint(64 - unsafe.Sizeof(bpfQueryAttr{}))
	_ = uint(unsafe.Sizeof(bpfQueryAttr{}) - 64)
)

// bpfIDAttr is the attribute union of the id-based commands: the id asked
// about, then the one the kernel answers with.
type bpfIDAttr struct {
	id   uint32
	next uint32
}

// bpfInfoAttr asks for an object's description in a buffer.
type bpfInfoAttr struct {
	descriptor uint32
	length     uint32
	info       uint64
}

// interfaceHook is one BPF attach point that carries a pod's packets on one
// of its interfaces.
type interfaceHook struct {
	name       string
	attachType uint32
	// mayBeAbsent marks a hook that exists only on some devices and kernels:
	// its query's ENXIO or EINVAL answers "no programs", never an error.
	mayBeAbsent bool
}

// interfaceHooks are the hooks checked on every interface of the pod: the
// tcx hooks every interface has, and the netkit hooks a netkit one has.
var interfaceHooks = []interfaceHook{
	{name: "tcx ingress", attachType: bpfTcxIngress},
	{name: "tcx egress", attachType: bpfTcxEgress},
	{name: "netkit primary", attachType: bpfNetkitPrimary, mayBeAbsent: true},
	{name: "netkit peer", attachType: bpfNetkitPeer, mayBeAbsent: true},
}

// absent reports whether a hook query's error only says the hook does not
// exist: a netkit hook of another device type (netkit_dev_fetch's ENXIO) or
// on a kernel without netkit (the stub's EINVAL). A tcx hook exists on every
// interface, so its errors always leave the pod unverified.
func (h interfaceHook) absent(err error) bool {
	return h.mayBeAbsent && (errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EINVAL))
}

// podNetwork is what a BPF attachment would have to name to reach this pod.
type podNetwork struct {
	inode      uint64
	interfaces map[uint32]string
}

// readPodNetwork reads the pod's interfaces in the attached namespace, with
// the inode taken from the handle the caller named.
func readPodNetwork(inode uint64) (podNetwork, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return podNetwork{}, fmt.Errorf("list links: %w", err)
	}
	pod := podNetwork{
		inode:      inode,
		interfaces: map[uint32]string{},
	}
	for _, link := range links {
		pod.interfaces[uint32(link.Attrs().Index)] = link.Attrs().Name
	}
	return pod, nil
}

// requireNoPacketBPFLinks rejects a BPF attachment that carries or copies the
// pod's packets: a program on a hook of one of its interfaces, a netns link
// on its namespace, or a netfilter link anywhere on the node. It runs attached
// to the pod's namespace: the hook query resolves there.
func requireNoPacketBPFLinks(pod podNetwork) error {
	if pod.inode > math.MaxUint32 {
		return fmt.Errorf("namespace inode %d is wider than a link description", pod.inode)
	}
	for index, name := range pod.interfaces {
		if err := requireNoHookPrograms(index, name); err != nil {
			return err
		}
	}
	links, err := enumerateBPFLinks()
	if err != nil {
		return fmt.Errorf("enumerate BPF links: %w", err)
	}
	for _, link := range links {
		switch link.linkType {
		case bpfLinkTypeNetfilter:
			return mismatchf("netfilter BPF link on this node")
		case bpfLinkTypeNetNS:
			if uint64(link.target) == pod.inode {
				return mismatchf("netns BPF link on this namespace")
			}
		}
	}
	return nil
}

// requireNoHookPrograms rejects a program on any packet hook of the pod's
// interface. The kernel resolves the interface in the attached namespace and
// reports the hook's programs however they were attached, so a host-side link
// — Cilium's tcx links on its lxc devices — never aliases in, whatever index
// its description carries.
func requireNoHookPrograms(index uint32, name string) error {
	for _, hook := range interfaceHooks {
		programs, err := queryHookPrograms(index, hook.attachType)
		if hook.absent(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("query %s on link %s: %w", hook.name, name, err)
		}
		if programs > 0 {
			return mismatchf("%s BPF program on link %s", hook.name, name)
		}
	}
	return nil
}

// liveBPFLinks walks every BPF link the kernel holds: a link is reachable by
// id only.
func liveBPFLinks() ([]bpfLink, error) {
	var links []bpfLink
	for id := uint32(0); ; {
		walk := bpfIDAttr{id: id}
		_, err := bpfCall(bpfLinkGetNextID, unsafe.Pointer(&walk), unsafe.Sizeof(walk))
		if errors.Is(err, unix.ENOENT) {
			return links, nil
		}
		if err != nil {
			return nil, err
		}
		next := walk.next
		if next <= id {
			return nil, fmt.Errorf("BPF link id %d does not follow %d", next, id)
		}
		link, err := readBPFLink(next)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
		id = next
	}
}

// liveHookPrograms asks the kernel how many programs one hook of one
// interface holds, resolved in the attached namespace.
func liveHookPrograms(ifindex, attachType uint32) (int, error) {
	query := bpfQueryAttr{
		target:     ifindex,
		attachType: attachType,
	}
	if _, err := bpfCall(bpfProgQuery, unsafe.Pointer(&query), unsafe.Sizeof(query)); err != nil {
		return 0, err
	}
	return int(query.count), nil
}

func readBPFLink(id uint32) (bpfLink, error) {
	open := bpfIDAttr{id: id}
	descriptor, err := bpfCall(bpfLinkGetFDByID, unsafe.Pointer(&open), unsafe.Sizeof(open))
	if err != nil {
		return bpfLink{}, fmt.Errorf("open BPF link %d: %w", id, err)
	}
	defer unix.Close(descriptor)
	info := make([]byte, bpfLinkInfoSize)
	query := bpfInfoAttr{
		descriptor: uint32(descriptor),
		length:     uint32(len(info)),
		info:       uint64(uintptr(unsafe.Pointer(&info[0]))),
	}
	_, err = bpfCall(bpfObjGetInfoByFD, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(info)
	if err != nil {
		return bpfLink{}, fmt.Errorf("describe BPF link %d: %w", id, err)
	}
	return readBPFLinkInfo(info)
}

// readBPFLinkInfo reads the fields of bpf_link_info this package decides on.
func readBPFLinkInfo(info []byte) (bpfLink, error) {
	if len(info) < bpfLinkInfoSize {
		return bpfLink{}, fmt.Errorf("BPF link description of %d bytes", len(info))
	}
	var described bpfLinkInfo
	if err := binary.Read(bytes.NewReader(info), binary.NativeEndian, &described); err != nil {
		return bpfLink{}, fmt.Errorf("decode a BPF link description: %w", err)
	}
	return bpfLink{
		linkType: described.LinkType,
		target:   described.Target,
	}, nil
}

func bpfCall(command int, attributes unsafe.Pointer, size uintptr) (int, error) {
	result, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(command), uintptr(attributes), size)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}
