// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	SyscallProbeEntryAccept  *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_accept"`
	SyscallProbeEntryAccept4 *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_accept4"`
	SyscallProbeEntryClose   *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_close"`
	SyscallProbeEntryRead    *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_read"`
	SyscallProbeEntryWrite   *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_write"`
	SyscallProbeRetAccept    *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_accept"`
	SyscallProbeRetAccept4   *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_accept4"`
	SyscallProbeRetClose     *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_close"`
	SyscallProbeRetRead      *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_read"`
	SyscallProbeRetWrite     *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_write"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	ActiveAcceptArgsMap       *ebpf.MapSpec `ebpf:"active_accept_args_map"`
	ActiveCloseArgsMap        *ebpf.MapSpec `ebpf:"active_close_args_map"`
	ActiveReadArgsMap         *ebpf.MapSpec `ebpf:"active_read_args_map"`
	ActiveWriteArgsMap        *ebpf.MapSpec `ebpf:"active_write_args_map"`
	AppPidMap                 *ebpf.MapSpec `ebpf:"app_pid_map"`
	ConnInfoMap               *ebpf.MapSpec `ebpf:"conn_info_map"`
	ReadCounter               *ebpf.MapSpec `ebpf:"read_counter"`
	ReadDataMap               *ebpf.MapSpec `ebpf:"read_data_map"`
	SocketCloseEvents         *ebpf.MapSpec `ebpf:"socket_close_events"`
	SocketDataEventBufferHeap *ebpf.MapSpec `ebpf:"socket_data_event_buffer_heap"`
	SocketDataEvents          *ebpf.MapSpec `ebpf:"socket_data_events"`
	SocketOpenEvents          *ebpf.MapSpec `ebpf:"socket_open_events"`
	WriteCounter              *ebpf.MapSpec `ebpf:"write_counter"`
	WriteDataMap              *ebpf.MapSpec `ebpf:"write_data_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	ActiveAcceptArgsMap       *ebpf.Map `ebpf:"active_accept_args_map"`
	ActiveCloseArgsMap        *ebpf.Map `ebpf:"active_close_args_map"`
	ActiveReadArgsMap         *ebpf.Map `ebpf:"active_read_args_map"`
	ActiveWriteArgsMap        *ebpf.Map `ebpf:"active_write_args_map"`
	AppPidMap                 *ebpf.Map `ebpf:"app_pid_map"`
	ConnInfoMap               *ebpf.Map `ebpf:"conn_info_map"`
	ReadCounter               *ebpf.Map `ebpf:"read_counter"`
	ReadDataMap               *ebpf.Map `ebpf:"read_data_map"`
	SocketCloseEvents         *ebpf.Map `ebpf:"socket_close_events"`
	SocketDataEventBufferHeap *ebpf.Map `ebpf:"socket_data_event_buffer_heap"`
	SocketDataEvents          *ebpf.Map `ebpf:"socket_data_events"`
	SocketOpenEvents          *ebpf.Map `ebpf:"socket_open_events"`
	WriteCounter              *ebpf.Map `ebpf:"write_counter"`
	WriteDataMap              *ebpf.Map `ebpf:"write_data_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.ActiveAcceptArgsMap,
		m.ActiveCloseArgsMap,
		m.ActiveReadArgsMap,
		m.ActiveWriteArgsMap,
		m.AppPidMap,
		m.ConnInfoMap,
		m.ReadCounter,
		m.ReadDataMap,
		m.SocketCloseEvents,
		m.SocketDataEventBufferHeap,
		m.SocketDataEvents,
		m.SocketOpenEvents,
		m.WriteCounter,
		m.WriteDataMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	SyscallProbeEntryAccept  *ebpf.Program `ebpf:"syscall__probe_entry_accept"`
	SyscallProbeEntryAccept4 *ebpf.Program `ebpf:"syscall__probe_entry_accept4"`
	SyscallProbeEntryClose   *ebpf.Program `ebpf:"syscall__probe_entry_close"`
	SyscallProbeEntryRead    *ebpf.Program `ebpf:"syscall__probe_entry_read"`
	SyscallProbeEntryWrite   *ebpf.Program `ebpf:"syscall__probe_entry_write"`
	SyscallProbeRetAccept    *ebpf.Program `ebpf:"syscall__probe_ret_accept"`
	SyscallProbeRetAccept4   *ebpf.Program `ebpf:"syscall__probe_ret_accept4"`
	SyscallProbeRetClose     *ebpf.Program `ebpf:"syscall__probe_ret_close"`
	SyscallProbeRetRead      *ebpf.Program `ebpf:"syscall__probe_ret_read"`
	SyscallProbeRetWrite     *ebpf.Program `ebpf:"syscall__probe_ret_write"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.SyscallProbeEntryAccept,
		p.SyscallProbeEntryAccept4,
		p.SyscallProbeEntryClose,
		p.SyscallProbeEntryRead,
		p.SyscallProbeEntryWrite,
		p.SyscallProbeRetAccept,
		p.SyscallProbeRetAccept4,
		p.SyscallProbeRetClose,
		p.SyscallProbeRetRead,
		p.SyscallProbeRetWrite,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel_x86.o
var _BpfBytes []byte
