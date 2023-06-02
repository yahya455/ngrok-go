package proto

import (
	"time"

	"golang.ngrok.com/ngrok/internal/muxado"
	"golang.ngrok.com/ngrok/internal/pb"
)

type ReqType muxado.StreamType

// NOTE(alan)
// never change the number of a message type that has already been assigned,
// you will break the protocol
const (
	// sent from the client to the server
	AuthReq                 ReqType = 0
	BindReq                 ReqType = 1
	UnbindReq               ReqType = 2
	StartTunnelWithLabelReq ReqType = 7

	// sent from the server to the client
	ProxyReq   ReqType = 3
	RestartReq ReqType = 4
	StopReq    ReqType = 5
	UpdateReq  ReqType = 6

	// sent from client to the server
	SrvInfoReq ReqType = 8
)

const Version = "2"

// When a client opens a new control channel to the server it must start by
// sending an Auth message.
type Auth struct {
	Version  []string  // protocol versions supported, ordered by preference
	ClientID string    `json:"ClientId"` // empty for new sessions
	Extra    AuthExtra // clients may add whatever data the like to auth messages
}

type ObfuscatedString string

func (t ObfuscatedString) String() string {
	return "HIDDEN"
}

func (t ObfuscatedString) PlainText() string {
	return string(t)
}

type AuthExtra struct {
	OS                 string
	Arch               string
	Authtoken          ObfuscatedString
	Version            string
	Hostname           string
	UserAgent          string
	Metadata           string
	Cookie             string
	HeartbeatInterval  int64
	HeartbeatTolerance int64
	Fingerprint        *Fingerprint

	// for each remote operation, these variables define whether the ngrok
	// client is capable of executing that operation. each capability
	// is transmitted as a pointer to string, with the following meanings:
	//
	// null ->               operation disallow beause the ngrok agent version is too old.
	//                       this is true because older clients will never set this value
	//
	// "" (empty string)  -> the operation is supported
	//
	// non-empty string   -> the operation is not supported and this value is the  user-facing
	//                       error message describing why it is not supported
	UpdateUnsupportedError  *string
	StopUnsupportedError    *string
	RestartUnsupportedError *string

	ProxyType       string
	MutualTLS       bool
	ServiceRun      bool
	ConfigVersion   string
	CustomInterface bool
	CustomCAs       bool

	ClientType ClientType // The type of client this is. Currently agent and library clients are supported
}

type ClientType string

const (
	LibraryOfficialGo ClientType = "ngrok-go"
)

// Note: entirely unused
type Fingerprint struct {
	M []string
	D []string
}

// A server responds to an Auth message with an
// AuthResp message over the control channel.Mutual
//
// If Error is not the empty string
// the server has indicated it will not accept
// the new session and will close the connection.
//
// The server response includes a unique ClientId
// that is used to associate and authenticate future
// proxy connections via the same field in RegProxy messages.
type AuthResp struct {
	Version  string // protocol version chosen
	ClientID string `json:"ClientId"`
	Error    string
	Extra    AuthRespExtra
}

type AgentVersionDeprecated struct {
	NextMin  string
	NextDate time.Time
	Msg      string
}

func (avd *AgentVersionDeprecated) Error() string {
	when := "at your earliest convenience."
	to := ""
	if !avd.NextDate.IsZero() {
		when = "by " + avd.NextDate.Format(time.DateOnly) + "."
	}
	if avd.NextMin != "" {
		to = "to " + avd.NextMin + " or later "
	}
	return "Your agent is deprecated. Please update " + to + when

}

type AuthRespExtra struct {
	Version string // server version
	Region  string // server region
	// Encrypted server.PersistentSession object.
	Cookie      string
	AccountName string
	// Duration in seconds
	SessionDuration    int64
	PlanName           string
	Banner             string
	DeprecationWarning *AgentVersionDeprecated
}

// A client sends this message to the server over a new stream
// to request the server bind a remote port/hostname on the client's behalf.
type Bind struct {
	ID         string    `json:"-"`
	ClientID   string    `json:"Id"` // a session-unique bind ID generated by the client, if empty, one is generated
	Proto      string    // the protocol to bind (one of 'http', 'https', 'tcp', 'tls', 'ssh')
	ForwardsTo string    // the address of the upstream service the ngrok agent will forward to
	Opts       any       // options for the bind - protocol dependent
	Extra      BindExtra // anything extra the application wants to send
}

type BindExtra struct {
	Token       string
	IPPolicyRef string
	Metadata    string
}

// The server responds with a BindResp message to notify the client of the
// success or failure of a bind.
type BindResp struct {
	ClientID string        `json:"Id"` // a session-unique bind ID generated by the client, if empty, one is generated
	URL      string        // public URL of the bind (a human friendly combination of Hostname/Port/Proto/Opts)
	Proto    string        // protocol bound on
	Opts     any           // protocol-specific options that were chosen
	Error    string        // error message is the server failed to bind
	Extra    BindRespExtra // application-defined extra values
}

type BindRespExtra struct {
	Token string
}

// A client sends this message to the server over a new stream
// to request the server start a new tunnel with the given labels on the client's behalf.
type StartTunnelWithLabel struct {
	// ID       string            `json:"-"` // a session-unique bind ID generated by the client, if empty, one is generated
	Labels     map[string]string // labels for tunnel group membership
	ForwardsTo string            // the address of the upstream service the ngrok agent will forward to
	Metadata   string
}

// The server responds with a StartTunnelWithLabelResp message to notify the client of the
// success or failure of the tunnel and label creation.
type StartTunnelWithLabelResp struct {
	ID    string `json:"Id"`
	Error string // error message is the server failed to bind
}

type ProxyProto int32

// in sync with rpx.Tunnel_ProxyProto
const (
	ProxyProtoNone = 0
	ProxyProtoV1   = 1
	ProxyProtoV2   = 2
)

func ParseProxyProto(proxyProto string) (ProxyProto, bool) {
	switch proxyProto {
	case "":
		return ProxyProtoNone, true
	case "1":
		return ProxyProtoV1, true
	case "2":
		return ProxyProtoV2, true
	default:
		return ProxyProtoNone, false
	}
}

type HTTPEndpoint struct {
	Domain            string
	Hostname          string // public hostname of the bind
	Subdomain         string
	Auth              string
	HostHeaderRewrite bool   // true if the request's host header is being rewritten
	LocalURLScheme    string // scheme of the local forward
	ProxyProto

	// middleware
	Compression           *pb.MiddlewareConfiguration_Compression
	CircuitBreaker        *pb.MiddlewareConfiguration_CircuitBreaker
	IPRestriction         *pb.MiddlewareConfiguration_IPRestriction
	BasicAuth             *pb.MiddlewareConfiguration_BasicAuth
	OAuth                 *pb.MiddlewareConfiguration_OAuth
	OIDC                  *pb.MiddlewareConfiguration_OIDC
	WebhookVerification   *pb.MiddlewareConfiguration_WebhookVerification
	MutualTLSCA           *pb.MiddlewareConfiguration_MutualTLS
	RequestHeaders        *pb.MiddlewareConfiguration_Headers
	ResponseHeaders       *pb.MiddlewareConfiguration_Headers
	WebsocketTCPConverter *pb.MiddlewareConfiguration_WebsocketTCPConverter
}

type TCPEndpoint struct {
	Addr string
	ProxyProto

	// middleware
	IPRestriction *pb.MiddlewareConfiguration_IPRestriction
}

type TLSEndpoint struct {
	Domain    string
	Hostname  string // public hostname of the bind
	Subdomain string
	ProxyProto
	MutualTLSAtAgent bool

	// edge termination options
	MutualTLSAtEdge *pb.MiddlewareConfiguration_MutualTLS
	TLSTermination  *pb.MiddlewareConfiguration_TLSTermination
	IPRestriction   *pb.MiddlewareConfiguration_IPRestriction
}

type SSHOptions struct {
	Hostname string // public hostname of the bind
	Username string
	Password string
	ProxyProto
}

type LabelOptions struct {
	Labels map[string]string
}

// A client sends this message to the server over a new stream to request the
// server close a bind
type Unbind struct {
	ID       string `json:"-"`
	ClientID string `json:"Id"` // Id of the bind to close
	Extra    any    // application-defined
}

// The server responds with an UnbindResp message to notify the client of the
// success or failure of the unbind.
type UnbindResp struct {
	Error string // an error, if the unbind failed
	Extra any    // application-defined
}

type EdgeType int32

// in sync with rpx.EdgesTypes_Edge
const (
	EdgeTypeUndefined EdgeType = 0
	EdgeTypeTCP                = 1
	EdgeTypeTLS                = 2
	EdgeTypeHTTPS              = 3
)

func ParseEdgeType(et string) (EdgeType, bool) {
	switch et {
	case "", "0":
		return EdgeTypeUndefined, true
	case "1":
		return EdgeTypeTCP, true
	case "2":
		return EdgeTypeTLS, true
	case "3":
		return EdgeTypeHTTPS, true
	default:
		return EdgeTypeUndefined, false
	}
}

// This message is sent first over a new stream from the server to the client to
// provide it with metadata about the connection it will tunnel over the stream.
type ProxyHeader struct {
	ID             string `json:"Id"` // Bind ID this connection is being proxied for
	ClientAddr     string // Network address of the client initiating the connection to the tunnel
	Proto          string // Protocol of the stream
	EdgeType       string // Type of edge
	PassthroughTLS bool   // true if the session is passing tls encrypted traffic to the agent
}

// This request is sent from the server to the ngrok agent asking it to immediately terminate itself
type Stop struct{}

// This client responds with StopResponse to the ngrok server to acknowledge it will shutdown
type StopResp struct {
	Error string // an error, if one occurred, while requesting a Stop
}

// This request is sent from the server to the ngrok agent asking it to restart itself
type Restart struct{}

// The client responds with RestartResponse to the ngrok server to acknowledge it will restart
type RestartResp struct {
	Error string // an error, if one occurred, while trying to restart. empty on OK
}

// This request is sent from the server to the ngrok agent asking it to update itself to
// a new version.
type Update struct {
	Version            string // the version to update to. if empty, the ngrok agent will update itself to the latest version
	PermitMajorVersion bool   // whether the caller has permitted a major version update
}

// The client responds with UpdateResponse to the ngrok server to acknowledge it will update
type UpdateResp struct {
	Error string // an error, if one
}

type SrvInfo struct{}

type SrvInfoResp struct {
	Region string
}
