package network

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

// Enforcer applies a Policy by acting as a filtering HTTP CONNECT proxy.
type Enforcer struct {
	policy *Policy
}

func NewEnforcer(policy *Policy) *Enforcer {
	return &Enforcer{policy: policy}
}

// ProxyHandler returns an http.Handler suitable for use as a local CONNECT proxy.
// Set HTTP_PROXY / HTTPS_PROXY env vars in the container to point at this listener.
func (e *Enforcer) ProxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, portStr, err := net.SplitHostPort(r.Host)
		if err != nil {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		port := 0
		fmt.Sscan(portStr, &port)

		if !e.policy.Allows(host, port) {
			http.Error(w,
				fmt.Sprintf("network policy: connection to %s:%d denied", host, port),
				http.StatusForbidden)
			return
		}

		dest, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer dest.Close()

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer clientConn.Close()
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		done := make(chan struct{}, 1)
		go func() {
			io.Copy(dest, clientConn)
			done <- struct{}{}
		}()
		io.Copy(clientConn, dest)
		<-done
	})
}
