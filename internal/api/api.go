// Package api is the local API between the daemon and its clients,
// ARCHITECTURE.md 6.2: JSON Lines over a Unix socket. A response carries the
// same envelope `--json` prints, plus the request id, so the CLI prints what
// it receives.
package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
)

// Version is the protocol's major version.
const Version = 1

// MaxMessage bounds one request or response line, 6.2.
const MaxMessage = 8 << 20

// Request is one call.
type Request struct {
	V      int             `json:"v"`
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is one reply line. A streaming method sends several with the
// same id; the last has Done set.
type Response struct {
	ID     int             `json:"id"`
	Done   bool            `json:"done,omitempty"`
	Schema string          `json:"schema"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cli.Error      `json:"error,omitempty"`
}

// Envelope is the response without the transport fields, as --json prints.
func (r Response) Envelope() any {
	if r.OK {
		return struct {
			Schema string          `json:"schema"`
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result,omitempty"`
		}{r.Schema, true, r.Result}
	}
	return struct {
		Schema string     `json:"schema"`
		OK     bool       `json:"ok"`
		Error  *cli.Error `json:"error"`
	}{r.Schema, false, r.Error}
}

// Client is one connection to the daemon.
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	nextID  int
	timeout time.Duration
}

// Dial connects to the daemon's socket. The errors are registered codes the
// CLI prints as they are.
func Dial(socket string) (*Client, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EACCES):
			return nil, cli.Errorf(cli.CodeAPIPermission, "用 admin 组的账户运行，或者加 sudo", "没有权限连接 daemon")
		default:
			return nil, cli.Errorf(cli.CodeDaemonUnreachable, "先运行 sudo xdial daemon install，或者确认 daemon 在运行", "连不上 daemon：%v", err)
		}
	}
	return &Client{conn: conn, reader: bufio.NewReaderSize(conn, 64<<10), timeout: 2 * time.Minute}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call sends one request and hands every response line to each until Done
// or a non-streaming reply. each returns false to stop early.
func (c *Client) Call(method string, params any, each func(Response) bool) error {
	c.nextID++
	req := Request{V: Version, ID: c.nextID, Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}
	line, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(line) > MaxMessage {
		return cli.Errorf(cli.CodeUsage, "", "请求超过 %d 字节", MaxMessage)
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return cli.Errorf(cli.CodeDaemonUnreachable, "", "发给 daemon 时出错：%v", err)
	}
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
		resp, err := ReadResponse(c.reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return cli.Errorf(cli.CodeDaemonUnreachable, "", "daemon 关闭了连接")
			}
			return cli.Errorf(cli.CodeDaemonUnreachable, "", "读 daemon 的回复出错：%v", err)
		}
		if resp.ID != req.ID {
			return cli.Errorf(cli.CodeInternal, "", "daemon 回复的 id %d 不是 %d", resp.ID, req.ID)
		}
		if !each(resp) || resp.Done || method != "logs" {
			return nil
		}
	}
}

// ReadResponse reads one bounded line.
func ReadResponse(r *bufio.Reader) (Response, error) {
	line, err := readLine(r)
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("回复不是 JSON：%w", err)
	}
	return resp, nil
}

// ReadRequest reads one bounded request line.
func ReadRequest(r *bufio.Reader) (Request, error) {
	line, err := readLine(r)
	if err != nil {
		return Request{}, err
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return Request{}, fmt.Errorf("请求不是 JSON：%w", err)
	}
	return req, nil
}

// ErrTooLong is a line over MaxMessage.
var ErrTooLong = errors.New("一行超过上限")

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessage {
			return nil, ErrTooLong
		}
		if !isPrefix {
			return line, nil
		}
	}
}
