package format

import (
	"fmt"
	"strings"
)

type ClipDirection int

const (
	ClipLeft ClipDirection = iota
	ClipRight
	ClipMiddle
)

func Summarize(content string, length int, clip ClipDirection) string {
	if len(content) <= length {
		return content
	}

	if length <= 3 {
		if clip == ClipLeft {
			return content[:length]
		}
		if clip == ClipRight {
			return content[len(content)-length:]
		}
	}

	out := content

	if clip == ClipLeft {
		out = "..." + out[len(out)-length+3:]
	}
	if clip == ClipRight {
		out = out[:length-3] + "..."
	}

	if clip == ClipMiddle {
		totalLength := len(out)
		clipLength := length - 3

		halfClipLength := clipLength / 2
		out = out[:halfClipLength] + "..." + out[totalLength-halfClipLength:]
	}

	return out
}

func PrettyPrintMap[K comparable, V any](m map[K]V) string {
	s := make([]string, 0, len(m))
	for k, v := range m {
		s = append(s, fmt.Sprintf("%v: %v", k, v))
	}
	return fmt.Sprintf("(%s)", strings.Join(s, ", "))
}
