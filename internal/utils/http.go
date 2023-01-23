package utils

import (
	"context"
	"io"
	"net"
	"strings"

	ctls "crypto/tls"

	tls "github.com/refraction-networking/utls"

	req "github.com/imroc/req/v3"
)

func IsHTTPS(url string) bool {
	// check if start with https://
	return strings.HasPrefix(url, "https://")
}

type TLSConn struct {
	*tls.UConn
}

func (conn *TLSConn) ConnectionState() ctls.ConnectionState {
	cs := conn.UConn.ConnectionState()
	return ctls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
	}
}

func reqClient(insecure bool, SNI ...string) *req.Client {
	c := req.C()
	c.SetDialTLS(func(ctx context.Context, network, addr string) (net.Conn, error) {
		plainConn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]
		utlsConfig := &tls.Config{ServerName: hostname, NextProtos: c.GetTLSClientConfig().NextProtos, MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
		if len(SNI) > 0 && SNI[0] != "" {
			utlsConfig.ServerName = SNI[0]
		}
		conn := tls.UClient(plainConn, utlsConfig, tls.HelloChrome_106_Shuffle)
		return &TLSConn{conn}, nil
	})

	return c
}

func GET(url string, insecure bool, SNI ...string) (status int, body []byte, err error) {
	c := reqClient(insecure, SNI...)

	resp, err := c.R().Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func POST(url string, postform interface{}, insecure bool, SNI ...string) (status int, body []byte, err error) {
	c := reqClient(insecure, SNI...)
	resp, err := c.R().SetBodyJsonMarshal(postform).Post(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}
