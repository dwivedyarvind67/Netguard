
package firewall

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu" netguard ../../bpf/xdp_firewall.c

