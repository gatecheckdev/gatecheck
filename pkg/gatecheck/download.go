package gatecheck

import (
	"io"
	"net/http"
	"os"
	"strings"

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

	epssCacheSet    bool
	epssCacheOn     bool
	epssCacheDir    string
	epssCacheDirSet bool
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

// WithEPSSClient sets the HTTP client used for EPSS downloads.
func WithEPSSClient(client *http.Client) optionFunc {
	if client == nil {
		return func(_ *fetchOptions) {}
	}
	return func(o *fetchOptions) {
		o.epssClient = client
	}
}

// WithEPSSCache turns the local daily EPSS cache on or off for this call.
func WithEPSSCache(enabled bool) optionFunc {
	return func(o *fetchOptions) {
		o.epssCacheSet = true
		o.epssCacheOn = enabled
	}
}

// WithEPSSCacheDir stores cached EPSS files in dir.
func WithEPSSCacheDir(dir string) optionFunc {
	return func(o *fetchOptions) {
		if strings.TrimSpace(dir) == "" {
			return
		}
		o.epssCacheDir = dir
		o.epssCacheDirSet = true
	}
}

// Option configures EPSS and KEV fetch behavior.
type Option func(*fetchOptions)

type optionFunc = Option

func (o *fetchOptions) epssDownloadOptions() []epss.Option {
	opts := []epss.Option{
		epss.WithClient(o.epssClient),
		epss.WithURL(o.epssURL),
	}
	if o.epssCacheSet {
		opts = append(opts, epss.WithCache(o.epssCacheOn))
	}
	if o.epssCacheDirSet {
		opts = append(opts, epss.WithCacheDir(o.epssCacheDir))
	}
	return opts
}

func DownloadEPSS(w io.Writer, optionFuncs ...optionFunc) error {
	options := defaultOptions()
	for _, f := range optionFuncs {
		f(options)
	}

	return epss.DownloadData(w, options.epssDownloadOptions()...)
}

func DownloadKEV(w io.Writer, optionFuncs ...optionFunc) error {
	options := defaultOptions()
	for _, f := range optionFuncs {
		f(options)
	}

	return kev.DownloadData(w, kev.WithClient(options.kevClient), kev.WithURL(options.kevURL))
}
