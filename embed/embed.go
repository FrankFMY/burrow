package embed

import "embed"

//go:embed admin/*
var AdminFS embed.FS

//go:embed landing.html
var LandingHTML []byte
