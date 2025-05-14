package utils

import (
	"os"
)

func LoadFile(filename string) ([]byte, error) {
	var file *os.File
	var e error

	file, e = os.Open(filename)
	if e != nil {
		return nil, e
	}

	defer file.Close()

	stat, e := file.Stat()
	if e != nil {
		return nil, e
	}

	bs := make([]byte, stat.Size())
	_, e = file.Read(bs)
	if e != nil {
		return nil, e
	}

	return bs, nil
}
