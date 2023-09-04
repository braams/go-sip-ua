package main

import (
	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/transport"
	"github.com/gobwas/ws"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var (
	logger log.Logger
)

func init() {
	logger = utils.NewLogrusLogger(log.DebugLevel, "Client", nil)
}

type Connection struct {
	headers http.Header
	uri     string
	host    string
}

type Authenticator struct {
	Connections map[string]Connection
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{
		Connections: map[string]Connection{},
	}
}

func (a *Authenticator) NewFactory() transport.UpgraderFactory {
	return func(conn net.Conn) ws.Upgrader {
		logger.Infof("Connection: %s", conn.RemoteAddr())
		return a.NewUpgrader(conn)
	}
}

func (a *Authenticator) NewUpgrader(conn net.Conn) ws.Upgrader {
	c := Connection{
		headers: map[string][]string{},
	}
	u := ws.Upgrader{
		Protocol: func(val []byte) bool {
			return string(val) == "sip"
		},
		OnRequest: func(uri []byte) error {
			c.uri = string(uri)
			return nil
		},
		OnHost: func(host []byte) error {
			c.host = string(host)
			return nil
		},
		OnHeader: func(key, value []byte) error {
			c.headers.Add(string(key), string(value))
			return nil
		},
		OnBeforeUpgrade: func() (header ws.HandshakeHeader, err error) {
			// any checks here
			if len(c.headers) > 0 {
				return ws.HandshakeHeaderHTTP(http.Header{"Foo": []string{"Bar"}}), nil
			} else {
				return nil, ws.RejectConnectionError(ws.RejectionStatus(http.StatusForbidden))
			}
		},
	}
	a.Connections[conn.RemoteAddr().String()] = c
	return u
}

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	stack := stack.NewSipStack(&stack.SipStackConfig{
		UserAgent:  "Go Sip Client/example-client",
		Extensions: []string{"replaces", "outbound"},
		Dns:        "8.8.8.8"})

	a := NewAuthenticator()
	if err := stack.Listen("ws", "0.0.0.0:8090", &transport.WSConfig{UpgraderFactory: a.NewFactory()}); err != nil {
		logger.Panic(err)

	}
	for _, l := range utils.GetLoggers() {
		l.Logger.SetLevel(log.InfoLevel)
	}
	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		SipStack: stack,
	})
	ua.Log().SetLevel(log.InfoLevel)
	ua.InviteStateHandler = func(sess *session.Session, req *sip.Request, resp *sip.Response, state session.Status) {
		logger.Infof("InviteStateHandler: state => %v, type => %s", state, sess.Direction())

		switch state {
		case session.InviteReceived:
			//sess.ProvideAnswer(sess.RemoteSdp())
			//sess.Accept(sip.StatusCode(200))

		case session.Canceled:
			fallthrough
		case session.Failure:
			fallthrough
		case session.Terminated:

		}
	}

	ua.RegisterStateHandler = func(state account.RegisterState) {
		logger.Infof("RegisterStateHandler: user => %s, state => %v, expires => %v", state.Account.AuthInfo.AuthUser, state.StatusCode, state.Expiration)

	}
	stack.OnRequest("REGISTER", handleRegister)
	<-stop

	ua.Shutdown()
}

func handleRegister(request sip.Request, tx sip.ServerTransaction) {
	logger.Infof("handleRegister")
	headers := request.GetHeaders("Expires")

	var expires sip.Expires = 0
	if len(headers) > 0 {
		expires = *headers[0].(*sip.Expires)
	}

	resp := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", "")
	utils.BuildContactHeader("Contact", request, resp, &expires)
	tx.Respond(resp)

}
