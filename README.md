# Iron Session for Go

A secure, encrypted session implementation for Go, inspired by the Node.js `iron-session` package.

## Features

- **Encrypted sessions**: All session data is encrypted using AES-GCM
- **Integrity protection**: HMAC-SHA256 ensures data hasn't been tampered with
- **Secure defaults**: HttpOnly, Secure, and SameSite cookies by default
- **PBKDF2 key derivation**: Protection against brute force attacks
- **Context integration**: Easy access to sessions in HTTP handlers
- **Middleware support**: Drop-in session handling for HTTP servers

## Installation

```bash
go get github.com/sh4nnongoh/ironsession
```

## Quick Start
```go
package main

import (
    "fmt"
    "net/http"
    
    "github.com/sh4nnongoh/ironsession"
)

func main() {
    // Configure session
    opts := ironsession.DefaultOptions().
        WithPassword("your-very-long-secure-password-here").
        WithCookieName("myapp_session").
        WithTTL(86400) // 24 hours

    // Create session manager
    is, err := ironsession.New(opts)
    if err != nil {
        panic(err)
    }

    // Use middleware
    http.Handle("/", is.Middleware(http.HandlerFunc(handler)))
    
    http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Get session from context
    session, ok := ironsession.GetSessionFromContext(r.Context())
    if !ok {
        http.Error(w, "Session not found", http.StatusInternalServerError)
        return
    }

    // Use session
    count, _ := session.Get("count").(int)
    count++
    session.Set("count", count)

    fmt.Fprintf(w, "Visit count: %d", count)
}
```

## Testing
```bash
go test ./...
go test -v ./...
```