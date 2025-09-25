package types

import (
	"fmt"
)

type Direction int8

const (
	DirectionForward  Direction = 0
	DirectionBackward Direction = 1
)

func (d Direction) String() string {
	switch d {
	case DirectionForward:
		return "forward"
	case DirectionBackward:
		return "backward"
	default:
		return fmt.Sprintf("unknow(%d", int(d))
	}
}
