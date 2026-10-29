package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"github.com/kafeifei/xdial-next/internal/api"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/peercred"
)

// Limits of the local API, ARCHITECTURE.md 6.2.
const (
	maxConnections = 32
	maxRefusals    = 8
	requestTimeout = 5 * time.Minute
	refuseTimeout  = 5 * time.Second
	writeTimeout   = 30 * time.Second
)

// listen creates the socket. Who may call is decided from the kernel's peer
// credentials, so the socket is open to every local user and an
// unauthorized caller gets api.permission rather than a bare EACCES. The
// directory is root's and made fresh: whatever another user put at its
// path is removed, and if something takes the path again before it is
// made, listening fails instead of reusing it.
func (d *Daemon) listen() (*net.UnixListener, error) {
	dir := d.opts.Layout.SocketDir()
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, 0); err != nil {
			return nil, err
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: d.opts.Layout.Socket(), Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(d.opts.Layout.Socket(), 0o666); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// serve authorizes each connection as it is accepted, before it takes one
// of the maxConnections slots, so callers who may not use the daemon cannot
// crowd out those who may. Refusals have their own small pool with a short
// deadline; past it, a connection is closed without an answer.
func (d *Daemon) serve(listener *net.UnixListener) error {
	slots := make(chan struct{}, maxConnections)
	refusals := make(chan struct{}, maxRefusals)
	refuse := func(conn *net.UnixConn, err error) {
		select {
		case refusals <- struct{}{}:
			go func() {
				defer func() { <-refusals }()
				answer(conn, err)
			}()
		default:
			conn.Close()
		}
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		uid, err := peercred.UID(conn)
		if err != nil || !d.opts.Authorize(uid) {
			refuse(conn, permissionError(uid))
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				d.handle(conn, uid)
			}()
		default:
			refuse(conn, cli.Errorf(cli.CodeDaemonBusy, "", "daemon 已有 %d 个连接", maxConnections))
		}
	}
}

func permissionError(uid uint32) error {
	return cli.Errorf(cli.CodeAPIPermission, "", "uid %d 不能使用 daemon：只有 root 和当前在屏幕前登录的用户可以", uid)
}

// answer replies to the first request on a connection with err, by its id,
// and hangs up.
func answer(conn *net.UnixConn, err error) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(refuseTimeout))
	req, _ := api.ReadRequest(bufio.NewReaderSize(conn, 4<<10))
	writeResponse(conn, failure(req.ID, err))
}

// handle serves one connection, one request at a time and in order. Each
// request is authorized again, so a user who is no longer at the console
// is refused from the next request on.
func (d *Daemon) handle(conn *net.UnixConn, uid uint32) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 64<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
		req, err := api.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, api.ErrTooLong) {
				writeResponse(conn, api.Response{Schema: cli.ErrorSchema, Error: cli.Errorf(cli.CodeUsage, "", "请求超过 %d 字节", api.MaxMessage)})
			}
			return
		}
		if !d.opts.Authorize(uid) {
			writeResponse(conn, failure(req.ID, permissionError(uid)))
			return
		}
		if !d.dispatch(conn, req, uid) {
			return
		}
	}
}

// reply is what a method returns: one result, or an error with a code.
type reply struct {
	schema string
	result any
	err    error
}

func (d *Daemon) dispatch(conn *net.UnixConn, req api.Request, uid uint32) bool {
	if req.V != api.Version {
		return writeResponse(conn, failure(req.ID, cli.Errorf(cli.CodeAPIVersion, "", "协议版本 %d 不认识，daemon 用的是 %d", req.V, api.Version)))
	}
	if req.Method == "logs" {
		return d.logs(conn, req, uid)
	}
	handler, ok := d.methods()[req.Method]
	if !ok {
		return writeResponse(conn, failure(req.ID, cli.Errorf(cli.CodeUsage, "", "daemon 没有方法 %q", req.Method)))
	}
	r := handler(req.Params)
	if r.err != nil {
		return writeResponse(conn, failure(req.ID, r.err))
	}
	result, err := marshal(r.result)
	if err != nil {
		return writeResponse(conn, failure(req.ID, err))
	}
	return writeResponse(conn, api.Response{ID: req.ID, Schema: r.schema, OK: true, Result: result})
}

func failure(id int, err error) api.Response {
	var e *cli.Error
	if !errors.As(err, &e) {
		e = &cli.Error{Code: cli.CodeInternal, Message: err.Error()}
	}
	return api.Response{ID: id, Schema: cli.ErrorSchema, Error: e}
}

// marshal encodes v without escaping HTML, which would make names with
// < > & up to six times longer.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

func writeResponse(conn net.Conn, resp api.Response) bool {
	line, err := marshal(resp)
	if err != nil {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = conn.Write(append(line, '\n'))
	return err == nil
}

func decode(params json.RawMessage, v any) error {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, v); err != nil {
		return cli.Errorf(cli.CodeUsage, "", "参数不对：%v", err)
	}
	return nil
}

// logs streams events: the recent ones, then new ones while follow is set
// and the client stays.
func (d *Daemon) logs(conn *net.UnixConn, req api.Request, uid uint32) bool {
	var params struct {
		Lines  int  `json:"lines"`
		Follow bool `json:"follow"`
	}
	if err := decode(req.Params, &params); err != nil {
		return writeResponse(conn, failure(req.ID, err))
	}
	if params.Lines <= 0 || params.Lines > recentLines {
		params.Lines = recentLines
	}
	send := func(e Event) bool {
		b, _ := json.Marshal(e)
		return writeResponse(conn, api.Response{ID: req.ID, Schema: "xdial.logs/v1", OK: true, Result: b})
	}
	var sub chan Event
	var past []Event
	if params.Follow {
		sub, past = d.events.follow(params.Lines)
		defer d.events.unsubscribe(sub)
	} else {
		past = d.events.recent(params.Lines)
	}
	for _, e := range past {
		if !send(e) {
			return false
		}
	}
	if !params.Follow {
		return writeResponse(conn, api.Response{ID: req.ID, Done: true, Schema: "xdial.logs/v1", OK: true, Result: json.RawMessage(`null`)})
	}
	closed := make(chan struct{})
	go func() {
		// The client ends a follow by closing its side.
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Time{})
		_, _ = conn.Read(buf)
		close(closed)
	}()
	for {
		select {
		case e := <-sub:
			// A follow outlives requests: ask again before every event, so
			// a user who left the console stops receiving them.
			if !d.opts.Authorize(uid) {
				writeResponse(conn, failure(req.ID, permissionError(uid)))
				return false
			}
			if !send(e) {
				return false
			}
		case <-closed:
			return false
		}
	}
}
