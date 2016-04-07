package json_encoder

import (
	"bytes"
	"strconv"

	"github.com/mozilla-services/heka/pipeline"
)

// COPIED FROM ELASTICSEARCH PLUGIN

const lowerhex = "0123456789abcdef"

const NEWLINE byte = 10

func writeUTF16Escape(b *bytes.Buffer, c rune) {
	b.WriteString(`\u`)
	b.WriteByte(lowerhex[(c>>12)&0xF])
	b.WriteByte(lowerhex[(c>>8)&0xF])
	b.WriteByte(lowerhex[(c>>4)&0xF])
	b.WriteByte(lowerhex[c&0xF])
}

func writeQuotedString(b *bytes.Buffer, str string) {
	b.WriteString(`"`)

	// string = quotation-mark *char quotation-mark

	// char = unescaped /
	//        escape (
	//            %x22 /          ; "    quotation mark  U+0022
	//            %x5C /          ; \    reverse solidus U+005C
	//            %x2F /          ; /    solidus         U+002F
	//            %x62 /          ; b    backspace       U+0008
	//            %x66 /          ; f    form feed       U+000C
	//            %x6E /          ; n    line feed       U+000A
	//            %x72 /          ; r    carriage return U+000D
	//            %x74 /          ; t    tab             U+0009
	//            %x75 4HEXDIG )  ; uXXXX                U+XXXX

	// escape = %x5C              ; \

	// quotation-mark = %x22      ; "

	// unescaped = %x20-21 / %x23-5B / %x5D-10FFFF

	for _, c := range str {
		if c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D) {
			b.WriteRune(c)
		} else {

			// All runes should be < 16 bits because of the (c >= 0x5D) guard
			// above. However, runes are int32 so it is possible to have
			// negative values that won't be correctly outputted. However,
			// afaik these values are not part of the unicode standard.
			writeUTF16Escape(b, c)
		}

	}
	b.WriteString(`"`)

}

func writeStringField(first bool, b *bytes.Buffer, name string, value string) {
	if !first {
		b.WriteString(`,`)
	}

	writeQuotedString(b, name)
	b.WriteString(`:`)
	writeQuotedString(b, value)
}

func writeIntField(first bool, b *bytes.Buffer, name string, value int32) {
	if !first {
		b.WriteString(`,`)
	}
	writeQuotedString(b, name)
	b.WriteString(`:`)
	b.WriteString(strconv.Itoa(int(value)))
}

// END COPIED

type JsonEncoder struct {
}

type JsonEncoderConfig struct {
}

func (e *JsonEncoder) ConfigSruct() interface{} {
	return &JsonEncoderConfig{}
}

func (e *JsonEncoder) Init(config interface{}) (err error) {
	return
}

func (e *JsonEncoder) Encode(pack *pipeline.PipelinePack) (output []byte, err error) {
	m := pack.Message
	buf := bytes.Buffer{}
	buf.WriteString(`{`)

	timestampFormat = "%Y-%m-%dT%H:%M:%S"
	t := time.Unix(0, m.GetTimestamp()).UTC()
	writeStringField(true, &buf, "Timestamp", gostrftime.Strftime(timestampFormat, t))
	writeStringField(true, &buf, "Type", m.GetType())
	writeStringField(false, &buf, "Host", m.GetHostname())
	writeStringField(false, &buf, "Payload", m.GetPayload())
	writeStringField(false, &buf, "Pid", m.GetPid())
	writeStringField(false, &buf, "Severity", m.GetSeverity())
	writeStringField(false, &buf, "Uuid", m.GetUuidString())
	
	writeIntField(false, &buf, "@version", 1)

	buf.WriteString(`}`)
	buf.WriteByte(NEWLINE)
	return buf.Bytes(), err

}

func init() {
	pipeline.RegisterPlugin("JsonEncoder", func() interface{} {
		return new(JsonEncoder)
	})
}
