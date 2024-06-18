package gatecheck

import (
	"io"
	"net/http"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
)

type fetchOptions struct {
	epssClient *http.Client
	epssURL    string

	kevClient *http.Client
	kevURL    string

	epssFile *os.File
	kevFile  *os.File
}

func defaultOptions() *fetchOptions {
	epssDefault := epss.DefaultFetchOptions()
	kevDefault := kev.DefaultFetchOptions()
	return &fetchOptions{
		epssClient: epssDefault.Client,
		epssURL:    epssDefault.URL,
		kevClient:  kevDefault.Client,
		kevURL:     kevDefault.URL,
	}
}

// WithEPSSURL optionFunc that sets the fetch URL for EPSS data
//
// Will use the default option if "" is passed
func WithEPSSURL(url string) optionFunc {
	if url == "" {
		return func(_ *fetchOptions) {}
	}

	return func(o *fetchOptions) {
		o.epssURL = url
	}
}

// WithKEVURL optionFunc that sets the fetch URL for KEV data
//
// Will use the default option if "" is passed
func WithKEVURL(url string) optionFunc {
	if url == "" {
		return func(_ *fetchOptions) {}
	}

	return func(o *fetchOptions) {
		o.kevURL = url
	}
}

func WithEPSSFile(epssFile *os.File) optionFunc {
	return func(o *fetchOptions) {
		o.epssFile = epssFile
	}
}

func WithKEVFile(kevFile *os.File) optionFunc {
	return func(o *fetchOptions) {
		o.kevFile = kevFile
	}
}

type optionFunc func(*fetchOptions)

func DownloadEPSS(w io.Writer, optionFuncs ...optionFunc) error {
	options := defaultOptions()
	for _, f := range optionFuncs {
		f(options)
	}

	return epss.DownloadData(w, epss.WithClient(options.epssClient), epss.WithURL(options.epssURL))
}

func DownloadKEV(w io.Writer, optionFuncs ...optionFunc) error {
	options := defaultOptions()
	for _, f := range optionFuncs {
		f(options)
	}

	return kev.DownloadData(w, kev.WithClient(options.kevClient), kev.WithURL(options.kevURL))
}
