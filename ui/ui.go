package ui

import (
	"fmt"
	"net/http"

	"github.com/spf13/viper"
)

func UI() http.Handler {
	assetsPath := viper.GetString("assets-path")

	var filesystem http.FileSystem
	if assetsPath != "" {
		fmt.Println("using ui assets path:", assetsPath)
		filesystem = http.Dir(assetsPath)
	} else {
		fmt.Println("using the built-in ui assets")
		filesystem = assetFS()
	}

	h := http.FileServer(filesystem)
	return &idpUI{h, http.StripPrefix("/SAML2/ui/", h)}
}

type idpUI struct {
	h             http.Handler
	prefixHandler http.Handler
}

func (s *idpUI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if "/favicon.ico" == req.URL.Path {
		s.h.ServeHTTP(w, req)
		return
	}
	s.prefixHandler.ServeHTTP(w, req)
}
