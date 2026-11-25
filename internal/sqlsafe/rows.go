package sqlsafe

import (
	"bytes"
	"strings"
)

// RowSet preserves column order and duplicate names. PostgreSQL's textual
// values remain strings, and nil represents SQL NULL.
type RowSet struct {
	Columns []string    `json:"columns"`
	Rows    [][]*string `json:"rows"`
}

// ParseCopyRows parses PostgreSQL COPY CSV with HEADER and FORCE_QUOTE *.
// FORCE_QUOTE marks every non-null value, including empty strings. Retaining
// the framing also preserves CRLF inside a quoted value.
func ParseCopyRows(output string) (*RowSet, error) {
	rows := &RowSet{Rows: make([][]*string, 0)}
	if output == "" {
		return nil, &ProtocolError{Reason: "missing row header"}
	}
	for output != "" {
		var record []*string
		var err error
		record, output, err = copyCSVRecord(output, rows.Columns != nil)
		if err != nil {
			return nil, err
		}
		if rows.Columns == nil {
			rows.Columns = make([]string, len(record))
			for i, field := range record {
				rows.Columns[i] = *field
			}
			continue
		}
		if len(record) != len(rows.Columns) {
			return nil, &ProtocolError{Reason: "row field count differs from header"}
		}
		rows.Rows = append(rows.Rows, record)
	}
	return rows, nil
}

func copyCSVRecord(input string, data bool) ([]*string, string, error) {
	var fields []*string
	for {
		var value *string
		if strings.HasPrefix(input, "\"") {
			decoded, rest, err := copyCSVQuoted(input[1:])
			if err != nil {
				return nil, "", err
			}
			value, input = &decoded, rest
		} else {
			end := strings.IndexAny(input, ",\r\n")
			if end < 0 || strings.Contains(input[:end], "\"") || data && end != 0 {
				return nil, "", &ProtocolError{Reason: "invalid unquoted row field"}
			}
			if !data {
				column := input[:end]
				value = &column
			}
			input = input[end:]
		}
		fields = append(fields, value)
		if rest, ok := strings.CutPrefix(input, ","); ok {
			input = rest
			continue
		}
		for _, newline := range []string{"\n", "\r\n"} {
			if rest, ok := strings.CutPrefix(input, newline); ok {
				return fields, rest, nil
			}
		}
		return nil, "", &ProtocolError{Reason: "missing row terminator"}
	}
}

func copyCSVQuoted(input string) (string, string, error) {
	var value bytes.Buffer
	for {
		field, rest, ok := strings.Cut(input, "\"")
		if !ok {
			return "", "", &ProtocolError{Reason: "unterminated quoted row field"}
		}
		value.WriteString(field)
		if !strings.HasPrefix(rest, "\"") {
			return value.String(), rest, nil
		}
		value.WriteByte('"')
		input = rest[1:]
	}
}
