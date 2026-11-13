package dnsrewrite

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	tcpIdleTimeout    = 10 * time.Second
	tcpWriteTimeout   = 5 * time.Second
	maxTCPConns       = 64
	maxQueriesPerConn = 256
)

// server serves DNS over UDP and TCP on one loopback address. Concurrency is
// bounded; excess UDP queries are dropped and excess TCP connections closed.
type server struct {
	res          *resolver
	queryTimeout time.Duration
	sem          chan struct{}
	tcpConns     chan struct{}
	wg           sync.WaitGroup
}

func newServer(res *resolver, upstreams int, upstreamTimeout time.Duration, maxConcurrent int) *server {
	return &server{
		res: res,
		// Every upstream attempt, each individually bounded.
		queryTimeout: time.Duration(upstreams) * upstreamTimeout,
		sem:          make(chan struct{}, maxConcurrent),
		tcpConns:     make(chan struct{}, maxTCPConns),
	}
}

func (s *server) serveUDP(ctx context.Context, pc *net.UDPConn) error {
	buf := make([]byte, maxDNSMessage)
	for {
		n, src, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !src.Addr().Unmap().IsLoopback() || n < dnsHeaderLen {
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			qctx, cancel := context.WithTimeout(ctx, s.queryTimeout)
			defer cancel()
			if resp := s.res.handle(qctx, query, false); resp != nil {
				_, _ = pc.WriteToUDPAddrPort(resp, src)
			}
		}()
	}
}

func (s *server) serveTCP(ctx context.Context, ln *net.TCPListener) error {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if remote, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || !remote.IP.IsLoopback() {
			_ = conn.Close()
			continue
		}
		select {
		case s.tcpConns <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.tcpConns }()
			s.serveConn(ctx, conn)
		}()
	}
}

func (s *server) serveConn(ctx context.Context, conn *net.TCPConn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var lenBuf [2]byte
	for range maxQueriesPerConn {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n < dnsHeaderLen {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := s.handleBlocking(ctx, query)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func (s *server) handleBlocking(ctx context.Context, query []byte) []byte {
	qctx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	select {
	case s.sem <- struct{}{}:
	case <-qctx.Done():
		return nil
	}
	defer func() { <-s.sem }()
	return s.res.handle(qctx, query, true)
}
