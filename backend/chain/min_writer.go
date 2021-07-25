package chain

import (
	"crypto/rand"
	"io"
)

type MinWriter struct {
	w         io.Writer
	bytesLeft int
}

func NewMinWriter(w io.Writer, minSize int) io.WriteCloser {
	return &MinWriter{w, minSize}
}

func (mw *MinWriter) Write(p []byte) (nn int, err error) {
	nn, err = mw.w.Write(p)
	if mw.bytesLeft > 0 && nn > 0 {
		mw.bytesLeft -= nn
		if mw.bytesLeft < 0 {
			mw.bytesLeft = 0
		}
	}

	return nn, err
}

func (mw *MinWriter) Close() error {
	if mw.bytesLeft > 0 {
		pp := make([]byte, mw.bytesLeft)
		rand.Read(pp)
		mw.w.Write(pp)
		mw.bytesLeft = 0
	}

	return nil
}
