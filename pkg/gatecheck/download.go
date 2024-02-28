package gatecheck

import (
	"io"
	"net/http"

	"github.com/gatecheckdev/gatecheck/pkg/epss/v1"
	"github.com/gatecheckdev/gatecheck/pkg/kev/v1"
)

type fetchOptions struct {
	epssClient *http.Client
	epssURL    string

	kevClient *http.Client
	kevURL    string

	epssFile io.Reader
	kevFile  io.Reader
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

func WithEPSSFile(r io.Reader) optionFunc {
	return func(o *fetchOptions) {
		o.epssFile = r
	}
}

func WithKEVFile(r io.Reader) optionFunc {
	return func(o *fetchOptions) {
		o.kevFile = r
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
