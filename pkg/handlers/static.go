package handlers

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/dashboard-sse.js
var staticFiles embed.FS

func newStaticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/static/", http.FileServerFS(sub))
}
