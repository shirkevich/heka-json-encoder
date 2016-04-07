package json_encoder

import (
	"bytes"
	"strconv"
	"time"
	"strings"
	"encoding/base64"
	"github.com/cactus/gostrftime"
	"github.com/mozilla-services/heka/message"
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
	typeNames []string
}

type JsonEncoderConfig struct {
}

func (e *JsonEncoder) ConfigSruct() interface{} {
	return &JsonEncoderConfig{}
}

func (e *JsonEncoder) Init(config interface{}) (err error) {
	e.typeNames = make([]string, len(message.Field_ValueType_name))
	for i, typeName := range message.Field_ValueType_name {
		e.typeNames[i] = strings.ToLower(typeName)
	}
	return
}

func (e *JsonEncoder) Encode(pack *pipeline.PipelinePack) (output []byte, err error) {
	m := pack.Message
	buf := bytes.Buffer{}
	buf.WriteString(`{`)

	timestampFormat := "%Y-%m-%dT%H:%M:%S"
	t := time.Unix(0, m.GetTimestamp()).UTC()
	writeStringField(true, &buf, "Timestamp", gostrftime.Strftime(timestampFormat, t))
	writeStringField(false, &buf, "Type", m.GetType())
	writeStringField(false, &buf, "Host", m.GetHostname())
	writeStringField(false, &buf, "Logger", m.GetLogger())
	writeStringField(false, &buf, "Payload", m.GetPayload())
	writeIntField(false, &buf, "Pid", m.GetPid())
	writeIntField(false, &buf, "Severity", m.GetSeverity())
	writeStringField(false, &buf, "Uuid", m.GetUuidString())
	writeIntField(false, &buf, "@version", 1)

	// Writing out the dynamic message fields is a bit of a PITA.
	fields := m.GetFields()
	if len(fields) > 0 {
		buf.WriteString(`,`)
		writeQuotedString(&buf, "Fields")
		buf.WriteString(`:{`)
		for fieldNum, field := range fields {
			firstField := fieldNum == 0
			valueType := field.GetValueType()
			//typeName := e.typeNames[valueType]
			var values []string
			switch valueType {
			case message.Field_STRING:
				values = field.GetValueString()
				writeStringField(firstField, &buf, field.GetName(), field.GetValueString()[0])

			case message.Field_BYTES:
				vBytes := field.GetValueBytes()
				values = make([]string, len(vBytes))
				for i, v := range vBytes {
					values[i] = base64.StdEncoding.EncodeToString(v)
				}
			case message.Field_DOUBLE:
				vDoubles := field.GetValueDouble()
				values = make([]string, len(vDoubles))
				for i, v := range vDoubles {
					values[i] = strconv.FormatFloat(v, 'g', -1, 64)
				}
			case message.Field_INTEGER:
				vInts := field.GetValueInteger()
				values = make([]string, len(vInts))
				for i, v := range vInts {
					values[i] = strconv.FormatInt(v, 10)
				}
				writeIntField(firstField, &buf, field.GetName(), int32(vInts[0]))
			case message.Field_BOOL:
				vBools := field.GetValueBool()
				values = make([]string, len(vBools))
				for i, v := range vBools {
					values[i] = strconv.FormatBool(v)
				}
			}
		}
		buf.WriteString(`}`)
	}

	buf.WriteString(`}`)
	buf.WriteByte(NEWLINE)
	return buf.Bytes(), err

}

func init() {
	pipeline.RegisterPlugin("JsonEncoder", func() interface{} {
		return new(JsonEncoder)
	})
}

