// Package peercred reads who is at the other end of a Unix socket, as the
// kernel recorded it when the connection was made, ARCHITECTURE.md 6.2. The
// daemon checks its callers with it and the clients check the daemon.
package peercred
