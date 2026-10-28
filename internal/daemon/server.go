package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"github.com/kafeifei/xdial-next/internal/api"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/store"
)

// Limits of the local API, ARCHITECTURE.md 6.2.
const (
	maxConnections = 16
	requestTimeout = 5 * time.Minute
	writeTimeout   = 30 * time.Second
)

// listen creates the socket in a directory only root and admin can enter:
// the directory is replaced, not reused, so nothing another user put there
// survives, and the socket is created inside it.
func (d *Daemon) listen() (*net.UnixListener, error) {
	dir := d.opts.Layout.SocketDir()
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := store.EnsureDir(dir, 0o750); err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, adminGroup); err != nil {
			return nil, err
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: d.opts.Layout.Socket(), Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(d.opts.Layout.Socket(), 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(d.opts.Layout.Socket(), 0, adminGroup); err != nil {
			listener.Close()
			return nil, err
		}
	}
	return listener, nil
}

func (d *Daemon) serve(listener *net.UnixListener) error {
	slots := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				d.handle(conn)
			}()
		default:
			conn.Close()
		}
	}
}

// handle serves one connection after checking who is on the other end with
// the kernel's credentials, not the socket's file permissions alone.
func (d *Daemon) handle(conn *net.UnixConn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 64<<10)
	uid, groups, err := peerCredentials(conn)
	if err != nil || !d.opts.Authorize(uid, groups) {
		// Answer the first request by its id, then hang up.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		req, _ := api.ReadRequest(reader)
		writeResponse(conn, failure(req.ID, cli.Errorf(cli.CodeAPIPermission, "", "只有 root 和 admin 组成员能使用 daemon")))
		return
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
		req, err := api.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, api.ErrTooLong) {
				writeResponse(conn, api.Response{Schema: cli.ErrorSchema, Error: cli.Errorf(cli.CodeUsage, "", "请求超过 %d 字节", api.MaxMessage)})
			}
			return
		}
		if !d.dispatch(conn, req) {
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

func (d *Daemon) dispatch(conn *net.UnixConn, req api.Request) bool {
	if req.V != api.Version {
		return writeResponse(conn, failure(req.ID, cli.Errorf(cli.CodeAPIVersion, "", "协议版本 %d 不认识，daemon 用的是 %d", req.V, api.Version)))
	}
	if req.Method == "logs" {
		return d.logs(conn, req)
	}
	handler, ok := d.methods()[req.Method]
	if !ok {
		return writeResponse(conn, failure(req.ID, cli.Errorf(cli.CodeUsage, "", "daemon 没有方法 %q", req.Method)))
	}
	r := handler(req.Params)
	if r.err != nil {
		return writeResponse(conn, failure(req.ID, r.err))
	}
	result, err := json.Marshal(r.result)
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

func writeResponse(conn net.Conn, resp api.Response) bool {
	line, err := json.Marshal(resp)
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
func (d *Daemon) logs(conn *net.UnixConn, req api.Request) bool {
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
	if params.Follow {
		sub = d.events.subscribe()
		defer d.events.unsubscribe(sub)
	}
	for _, e := range d.events.recent(params.Lines) {
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
			if !send(e) {
				return false
			}
		case <-closed:
			return false
		}
	}
}
