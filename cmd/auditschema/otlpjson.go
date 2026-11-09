package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
)

// record is one decoded LogRecord: the parts the schema checks.
type record struct {
	eventName string
	attrs     []attribute.KeyValue
}

// The OTLP/JSON shapes (opentelemetry-proto, JSON encoding: lowerCamelCase
// field names, int64 as a decimal string or a number, bytes as base64).
type jsonRequest struct {
	ResourceLogs []struct {
		ScopeLogs []struct {
			LogRecords []jsonLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type jsonLogRecord struct {
	EventName  string         `json:"eventName"`
	Attributes []jsonKeyValue `json:"attributes"`
}

type jsonKeyValue struct {
	Key   string       `json:"key"`
	Value jsonAnyValue `json:"value"`
}

type jsonAnyValue struct {
	StringValue *string         `json:"stringValue"`
	BoolValue   *bool           `json:"boolValue"`
	IntValue    json.RawMessage `json:"intValue"`
	DoubleValue *float64        `json:"doubleValue"`
	BytesValue  *string         `json:"bytesValue"`
	ArrayValue  *struct {
		Values []jsonAnyValue `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *struct {
		Values []jsonKeyValue `json:"values"`
	} `json:"kvlistValue"`
}

// decodeRecords reads an ExportLogsServiceRequest, one LogRecord, or a JSON
// array of LogRecords.
func decodeRecords(r io.Reader) ([]record, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	var lrs []jsonLogRecord
	switch {
	case len(raw) > 0 && raw[0] == '[':
		if err := json.Unmarshal(raw, &lrs); err != nil {
			return nil, err
		}
	default:
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, err
		}
		if _, ok := probe["resourceLogs"]; ok {
			var req jsonRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				return nil, err
			}
			for _, rl := range req.ResourceLogs {
				for _, sl := range rl.ScopeLogs {
					lrs = append(lrs, sl.LogRecords...)
				}
			}
		} else {
			var lr jsonLogRecord
			if err := json.Unmarshal(raw, &lr); err != nil {
				return nil, err
			}
			lrs = append(lrs, lr)
		}
	}
	out := make([]record, 0, len(lrs))
	for i, lr := range lrs {
		attrs := make([]attribute.KeyValue, 0, len(lr.Attributes))
		for _, kv := range lr.Attributes {
			v, err := kv.Value.value()
			if err != nil {
				return nil, fmt.Errorf("record %d, attribute %s: %w", i, kv.Key, err)
			}
			attrs = append(attrs, attribute.KeyValue{Key: attribute.Key(kv.Key), Value: v})
		}
		out = append(out, record{eventName: lr.EventName, attrs: attrs})
	}
	return out, nil
}

// value converts an OTLP AnyValue to an attribute value of the same kind.
func (a jsonAnyValue) value() (attribute.Value, error) {
	switch {
	case a.StringValue != nil:
		return attribute.StringValue(*a.StringValue), nil
	case a.BoolValue != nil:
		return attribute.BoolValue(*a.BoolValue), nil
	case len(a.IntValue) > 0:
		s := string(bytes.Trim(a.IntValue, `"`))
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return attribute.Value{}, fmt.Errorf("intValue: %w", err)
		}
		return attribute.Int64Value(n), nil
	case a.DoubleValue != nil:
		return attribute.Float64Value(*a.DoubleValue), nil
	case a.BytesValue != nil:
		b, err := base64.StdEncoding.DecodeString(*a.BytesValue)
		if err != nil {
			return attribute.Value{}, fmt.Errorf("bytesValue: %w", err)
		}
		return attribute.ByteSliceValue(b), nil
	case a.ArrayValue != nil:
		vs := make([]attribute.Value, len(a.ArrayValue.Values))
		for i, e := range a.ArrayValue.Values {
			v, err := e.value()
			if err != nil {
				return attribute.Value{}, err
			}
			vs[i] = v
		}
		return attribute.SliceValue(vs...), nil
	case a.KvlistValue != nil:
		kvs := make([]attribute.KeyValue, len(a.KvlistValue.Values))
		for i, kv := range a.KvlistValue.Values {
			v, err := kv.Value.value()
			if err != nil {
				return attribute.Value{}, err
			}
			kvs[i] = attribute.KeyValue{Key: attribute.Key(kv.Key), Value: v}
		}
		return attribute.MapValue(kvs...), nil
	}
	return attribute.Value{}, nil // an empty AnyValue
}
