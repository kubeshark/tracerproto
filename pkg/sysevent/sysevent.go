package sysevent

import (
	"encoding/gob"
	"io"
	"net"

	"github.com/aquasecurity/tracee/types/trace"
)

type SysEvent trace.Event

type Writer struct {
	enc *gob.Encoder
}

type Reader struct {
	dec *gob.Decoder
}

func NewReader(r io.Reader) Reader {
	return Reader{
		dec: gob.NewDecoder(r),
	}
}

func NewWriter(w io.Writer) Writer {
	return Writer{
		enc: gob.NewEncoder(w),
	}
}

func (s Writer) Write(ev any) error {
	return s.enc.Encode(ev)
}

func (s Reader) Read(ev any) error {
	if err := s.dec.Decode(ev); err != nil {
		return err
	}
	return nil
}

func init() {
	gob.Register(map[string]interface{}{})
	gob.Register(map[string]string{})
	gob.Register(trace.Event{})

	gob.Register(trace.ProtoHTTPResponse{})
	gob.Register(trace.ProtoHTTPRequest{})
	gob.Register(trace.PacketMetadata{})
	gob.Register(trace.ProtoHTTP{})

	gob.Register(trace.PktMeta{})
	gob.Register(net.IP{})
}
