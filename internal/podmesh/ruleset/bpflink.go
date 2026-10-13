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
	bpfLinkGetFDByID  = 30
	bpfLinkGetNextID  = 31
	bpfObjGetInfoByFD = 15

	bpfLinkTypeNetNS     = 5
	bpfLinkTypeNetfilter = 10
	bpfLinkTypeTCX       = 11
	bpfLinkTypeNetkit    = 13
)

// packetBPFLinks are the link types that carry or copy a pod's packets, with
// what in a description tells whether the link is this pod's. XDP is left out:
// the pod's own links report their XDP program.
var packetBPFLinks = map[uint32]struct {
	name  string
	scope bpfLinkScope
}{
	bpfLinkTypeTCX: {
		name:  "tcx",
		scope: scopeInterface,
	},
	bpfLinkTypeNetkit: {
		name:  "netkit",
		scope: scopeInterface,
	},
	bpfLinkTypeNetNS: {
		name:  "netns",
		scope: scopeNamespace,
	},
	bpfLinkTypeNetfilter: {
		name:  "netfilter",
		scope: scopeNode,
	},
}

// bpfLinkScope is what a link's description names. scopeNode is for a link
// that names neither an interface nor a namespace, so one anywhere on the node
// is refused.
type bpfLinkScope int

const (
	scopeInterface bpfLinkScope = iota
	scopeNamespace
	scopeNode
)

// enumerateBPFLinks is a var so tests can drive link decisions without CAP_BPF.
var enumerateBPFLinks = liveBPFLinks

// bpfLink is one BPF link as the kernel describes it.
type bpfLink struct {
	linkType uint32
	// target is the first field of the link type's info union: an interface
	// index, or a namespace inode for a netns link.
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

// podNetwork is what a BPF link would have to name to reach this pod.
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

// requireNoPacketBPFLinks rejects a BPF link that carries or copies the pod's
// packets: tcx and netkit on its interfaces, netns on its namespace, and
// netfilter anywhere on the node.
func requireNoPacketBPFLinks(pod podNetwork) error {
	if pod.inode > math.MaxUint32 {
		return fmt.Errorf("namespace inode %d is wider than a link description", pod.inode)
	}
	links, err := enumerateBPFLinks()
	if err != nil {
		return fmt.Errorf("enumerate BPF links: %w", err)
	}
	for _, link := range links {
		carrier, carriesPackets := packetBPFLinks[link.linkType]
		if !carriesPackets {
			continue
		}
		if where := pod.reachedBy(carrier.scope, link.target); where != "" {
			return mismatchf("%s BPF link %s", carrier.name, where)
		}
	}
	return nil
}

// reachedBy names where a link is attached when it sees this pod's packets,
// and nothing when it does not.
func (n podNetwork) reachedBy(scope bpfLinkScope, target uint32) string {
	switch scope {
	case scopeNode:
		return "on this node"
	case scopeNamespace:
		if uint64(target) == n.inode {
			return "on this namespace"
		}
	case scopeInterface:
		if name, attached := n.interfaces[target]; attached {
			return "on link " + name
		}
	}
	return ""
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
