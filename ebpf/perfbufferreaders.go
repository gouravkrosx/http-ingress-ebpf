package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	_ "strings"
	"unsafe"

	"http_ingress/settings"
	"http_ingress/structs"
	"http_ingress/connections"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
	_ "golang.org/x/sys/unix"
)

var PerfEventReaders []*perf.Reader
var RingEventReaders []*ringbuf.Reader

// LaunchPerfBufferConsumers launches socket events
func LaunchPerfBufferConsumers(objs bpfObjects, connectionFactory *connections.Factory, stopper chan os.Signal, logger *zap.Logger) {

	launchSocketOpenEvent(objs.SocketOpenEvents, connectionFactory, stopper, logger)
	launchSocketDataEvent(objs.SocketDataEvents, connectionFactory, stopper, logger)
	launchSocketCloseEvent(objs.SocketCloseEvents, connectionFactory, stopper, logger)
}

func launchSocketOpenEvent(openEventMap *ebpf.Map, connectionFactory *connections.Factory, stopper chan os.Signal, logger *zap.Logger) {

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	reader, err := perf.NewReader(openEventMap, os.Getpagesize())
	if err != nil {
		logger.Error("failed to create perf event reader of socketOpenEvent", zap.Error(err))
		return
	}
	// defer reader.Close()
	PerfEventReaders = append(PerfEventReaders, reader)

	go socketOpenEventCallback(reader, connectionFactory, logger)
}

func launchSocketDataEvent(dataEventMap *ebpf.Map, connectionFactory *connections.Factory, stopper chan os.Signal, logger *zap.Logger) {

	// Open a ringbuf event reader from userspace on the RING_BUF map
	// described in the eBPF C program.
	reader, err := ringbuf.NewReader(dataEventMap)
	if err != nil {
		logger.Error("failed to create ring buffer of socketDataEvent", zap.Error(err))
		return
	}
	// defer reader.Close()
	RingEventReaders = append(RingEventReaders, reader)

	go socketDataEventCallback(reader, connectionFactory, logger)

}

func launchSocketCloseEvent(closeEventMap *ebpf.Map, connectionFactory *connections.Factory, stopper chan os.Signal, logger *zap.Logger) {

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	reader, err := perf.NewReader(closeEventMap, os.Getpagesize())
	if err != nil {
		logger.Error("failed to create perf event reader of socketCloseEvent", zap.Error(err))
		return
	}
	// defer reader.Close()
	PerfEventReaders = append(PerfEventReaders, reader)

	go socketCloseEventCallback(reader, connectionFactory, logger)
}

var eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEvent{}))

func socketDataEventCallback(reader *ringbuf.Reader, connectionFactory *connections.Factory, logger *zap.Logger) {

	for {

		record, err := reader.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				logger.Error("failed to receive signal from ringbuf socketDataEvent reader", zap.Error(err))
				return
			}
			continue
		}

		data := record.RawSample
		if len(data) < eventAttributesSize {
			logger.Debug(fmt.Sprintf("Buffer's for SocketDataEvent is smaller (%d) than the minimum required (%d)", len(data), eventAttributesSize))
			continue
		} else if len(data) > structs.EventBodyMaxSize+eventAttributesSize {
			logger.Debug(fmt.Sprintf("Buffer's for SocketDataEvent is bigger (%d) than the maximum for the struct (%d)", len(data), structs.EventBodyMaxSize+eventAttributesSize))
			continue
		}

		var event structs.SocketDataEvent

		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			logger.Error("failed to decode the recieve data from ringbuf socketDataEvent reader", zap.Error(err))
			continue
		}
		event.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.ConnID).AddDataEvent(event)

	}
}

func socketOpenEventCallback(reader *perf.Reader, connectionFactory *connections.Factory, logger *zap.Logger) {
	for {

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.Error("failed to read from perf socketOpenEvent reader", zap.Error(err))
			continue
		}

		if record.LostSamples != 0 {
			logger.Debug("Unable to add samples to the socketOpenEvent array due to its full capacity", zap.Any("samples", record.LostSamples))
			continue
		}
		data := record.RawSample
		var event structs.SocketOpenEvent

		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			logger.Error("failed to decode the recieved data from perf socketOpenEvent reader", zap.Error(err))
			continue
		}

		event.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.ConnID).AddOpenEvent(event)
	}
}

func socketCloseEventCallback(reader *perf.Reader, connectionFactory *connections.Factory, logger *zap.Logger) {
	for {

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.Error("reading from perf socketCloseEvent reader", zap.Error(err))
			continue
		}

		if record.LostSamples != 0 {
			logger.Debug(fmt.Sprintf("perf socketCloseEvent array full, dropped %d samples", record.LostSamples))
			continue
		}
		data := record.RawSample

		var event structs.SocketCloseEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
			logger.Debug(fmt.Sprintf("Failed to decode received data: %+v", err))
			continue
		}

		event.TimestampNano += settings.GetRealTimeOffset()
		connectionFactory.GetOrCreate(event.ConnID).AddCloseEvent(event)
	}
}
