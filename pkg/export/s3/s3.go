// Package s3 defines a S3 type that's stored in Contexts.
package s3

import (
	"context"
	"io"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

//	────────────────────────────────────────────────────────────────────────────────

// UploadObject struct holds the values specific to each file upload.
type UploadObject struct {
	Key  string
	File io.Reader
}

// Service is the type of value stored in the Contexts.
// Service can be used to export scans to AWS S3.
type Service struct {
	Client          *http.Client
	Manager         *manager.Uploader
	Params          *s3.PutObjectInput
	BackoffDuration time.Duration // The interval for the exponential back off retry
	Retry           int
}

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// serviceKey is the key for service.Service values in Contexts. It is
// unexported; clients use service.NewContext and service.FromContext
// instead of using this key directly.
var serviceKey key

// NewContext returns a new Context that carries value s.
func NewContext(ctx context.Context, s *Service) context.Context {
	return context.WithValue(ctx, serviceKey, s)
}

// FromContext returns the Service value stored in ctx, if any.
func FromContext(ctx context.Context) (*Service, bool) {
	s, ok := ctx.Value(serviceKey).(*Service)
	return s, ok
}

func NewService(client *http.Client, manager *manager.Uploader, params *s3.PutObjectInput) Service {
	return Service{
		Client:          client,
		Manager:         manager,
		Params:          params,
		BackoffDuration: time.Second,
		Retry:           3,
	}
}

func (s Service) Export(ctx context.Context, r io.Reader, uploadObject UploadObject) error {
	c := make(chan error)

	go func() {
		var err error
		for i := 0; i < s.Retry; i++ {
			err = s.export(ctx, r, uploadObject)
			if err == nil {
				close(c)
				return
			}
			// Sleep for 2 ^ backoff, seconds
			sleepFor := time.Duration(int64(math.Pow(2, float64(i)))) * s.BackoffDuration
			log.Printf("Export Attempt %d / %d, will Retrying after %s. Error: %v\n", i+1, s.Retry,
				sleepFor.String(), err)
			time.Sleep(sleepFor)
		}
		c <- err
	}()

	for {
		select {
		case err, ok := <-c:
			if !ok {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s Service) export(ctx context.Context, r io.Reader, uploadObject UploadObject) error {
	log.Printf("DEBUGPRINT[1]: s3.go:97 (after func (s Service) export(ctx context.Cont…)")
	log.Printf("DEBUGPRINT[2]: s3.go:97: s=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", s, s)
	log.Printf("DEBUGPRINT[3]: s3.go:97: ctx=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", ctx, ctx)
	log.Printf("DEBUGPRINT[4]: s3.go:97: r=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", r, r)
	log.Printf("DEBUGPRINT[5]: s3.go:97: uploadObject=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", uploadObject, uploadObject)
	// res, err := uploader.Upload(ctx, &putObjectInput{
	// 	Bucket: "bucket",
	// 	Key:    "key",
	// 	Body:   bytes.NewReader([]byte("some-file-contents")),
	// }, func(u uploader) {
	// 	u.PartSize = 5 * 1024 * 1024
	// })
	// if err != nil {
	// 	log.Printf("error: %v", err)
	// 	return nil
	// }
	//

	var err error
	return err
}

// func (s Service) postScan(r io.Reader, scanType ScanType, e engagement) error {
// 	url := s.url + "/api/v2/import-scan/"
// 	// After getting an engagement, post the scan using a multipart form
// 	payload := &bytes.Buffer{}
// 	writer := multipart.NewWriter(payload)
// 	_ = writer.WriteField("engagement", strconv.Itoa(e.Id))
// 	_ = writer.WriteField("scan_type", string(scanType))
//
// 	filePart, _ := writer.CreateFormFile("file", fmt.Sprintf("%s report.json", scanType))
//
// 	// Copy the file content to the filePart
// 	if _, err := io.Copy(filePart, r); err != nil {
// 		return fmt.Errorf("Defect Dojo, can't write file to form %w\n", err)
// 	}
//
// 	contentType := writer.FormDataContentType()
// 	_ = writer.Close()
//
// 	req, _ := http.NewRequest(http.MethodPost, url, payload)
// 	req.Header.Set("Content-Type", contentType)
// 	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))
//
// 	res, err := s.client.Do(req)
// 	if err != nil {
// 		return err
// 	}
//
// 	if res.StatusCode != http.StatusCreated {
// 		msg, _ := io.ReadAll(res.Body)
// 		return fmt.Errorf("%w: POST '%s' unexpected response code %d msg: %s",
// 			RequestError, url, res.StatusCode, msg)
// 	}
//
// 	return nil
// }
//
// func (s Service) postJSON(url string, reqBody io.Reader) (resBody io.ReadCloser, err error) {
// 	req, _ := http.NewRequest(http.MethodPost, url, reqBody)
// 	req.Header.Set("Content-Type", contentTypeJSON)
// 	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))
//
// 	res, err := s.client.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	if res.StatusCode != http.StatusCreated {
// 		msg, _ := io.ReadAll(res.Body)
// 		return nil, fmt.Errorf("%w: GET '%s' unexpected response code %d: msg: %s",
// 			RequestError, url, res.StatusCode, string(msg))
// 	}
// 	return res.Body, nil
// }

//  ────────────────────────────────────────────────────────────────────────────────

// ToS3 is the entrypoint function that loads the AWS Config, constructs the Client Service,
// invokes the API Operation, and builds a new *s3.Client.
// builds a new *s3.Client.
// func ToS3(ctx context.Context, i awsS3.PutObjectInput) error {
// 	fmt.Println("──────────── ClientFor(ctx context.Context) *s3.Client ──────────────")
// 	fmt.Println("")
//
// 	// Loads the AWS Config
// 	cfg, err := config.LoadDefaultConfig(ctx)
// 	if err != nil {
// 		return err
// 	}
//
// 	// Constructs the Client Service
// 	client := s3.NewFromConfig(cfg)
//
// 	uploader := manager.NewUploader(client)
//
// 	// Invokes the API Operation
// 	output, err := uploader.Upload(ctx, &awsS3.PutObjectInput{
// 		Bucket: i.Bucket,
// 		Key:    i.Key,
// 		Body:   i.Body,
// 	})
// 	if err != nil {
// 		return err
// 	}
//
// 	fmt.Printf("File upload type: %T\n\nvalue: %v\n\n", output, output)
// 	return nil
// }

//  ────────────────────────────────────────────────────────────────────────────────
