package main

import (
	"crypto/sha256"
	"hash"
)

type DigestWorker struct {
	numberOfSalts int
	saltsBytes    [][]byte
	ctxs          []hash.Hash
}

func NewDigestWorker(salts []string, numberOfSalts int) *DigestWorker {
	worker := &DigestWorker{
		numberOfSalts: numberOfSalts,
	}

	if len(salts) > 0 {
		for _, salt := range salts {
			worker.saltsBytes = append(worker.saltsBytes, []byte(salt))
		}
	}

	return worker
}

func (dw *DigestWorker) Start() {
	dw.ctxs = make([]hash.Hash, dw.numberOfSalts)
	for i := 0; i < dw.numberOfSalts; i++ {
		ctx := sha256.New()
		if len(dw.saltsBytes) > 0 {
			ctx.Write(dw.saltsBytes[i])
		}
		dw.ctxs[i] = ctx
	}
}

func (dw *DigestWorker) End() [][]byte {
	result := make([][]byte, dw.numberOfSalts)
	for i, ctx := range dw.ctxs {
		result[i] = ctx.Sum(nil)
	}
	dw.ctxs = nil
	return result
}

func (dw *DigestWorker) Hash(data []byte) int {
	dataLength := len(data)

	if dataLength == 0 {
		return -1
	}

	if dw.numberOfSalts > 0 {
		for _, ctx := range dw.ctxs {
			ctx.Write(data)
		}
	}

	return dataLength
}
