// Package aws integrates aws-sdk-go-v2 into gatecheck
package aws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
)

//  --------------------------------------------------------------------------------

//  #############################
//  # DoAWS WIP Builder Section #
//  #############################

type Upload struct {
	File []byte
	Key  string
}

func NewUpload(ddProductTypeName, ddProductName, ddEngagementName, filepath string) Upload {
	key := ddProductTypeName + "/" + ddProductName + "/" + ddEngagementName + "/" + filepath
	return Upload{
		Key: key,
	}
}

type AWS interface {
	Export(context.Context, io.Reader, Upload) error
}

type Service struct {
	Bucket  string
	Profile string
}

func NewService(bucket, profile string) Service {
	return Service{
		Bucket:  bucket,
		Profile: profile,
	}
}

func (s Service) Export(ctx context.Context, r io.Reader, upload Upload) error {
	log.Printf("DEBUGPRINT[5]: s3.go:43: upload=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", upload, upload)
	log.Printf("DEBUGPRINT[6]: s3.go:42: s=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", s, s)

	var err error
	// if err != nil {
	// 	log.Printf("error: %v", err)
	// 	return err
	// }
	return err
}

//  ---------------------- AWS Config ----------------------------------------------

type Profile struct {
	Name string
}

func (profile *Profile) ConfigInputs() {
	fmt.Println("--------------------------- Profile.Inputs() ------------------------------")
	fmt.Println("")
	fmt.Printf("Received *Profile: %v", profile)
	fmt.Println("")
	fmt.Println("")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(profile.Name))
	if err != nil {
		log.Printf("error: %v", err)
		return
	}

	log.Printf("DEBUGPRINT[4]: s3.go:40: cfg=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", cfg, cfg)
}

//  ---------------------- S3PutObjectInput ----------------------------------------

type S3PutObject struct {
	Bucket string
	Key    string
	Body   io.Reader // bytes.NewReader([]bytes)
}

func (s3PutObject *S3PutObject) S3PutObjectInputs() {
	fmt.Println("--------------------------- S3PutObject.Inputs() ------------------------------")
	fmt.Println("")
	fmt.Println("In Inputs()")
	fmt.Println("")
	fmt.Printf("Received *S3PutObject: %v", s3PutObject)
	fmt.Println("")

	s3PutObject.Key = "my-updated-key"
	s3PutObject.Body = bytes.NewReader([]byte("my-updated-body"))

	fmt.Printf("Updated *S3PutObject: %v", s3PutObject)
	fmt.Println("")

	fmt.Printf("S3PutObject.Bucket Value: %v", s3PutObject.Bucket)
	fmt.Println("")
	fmt.Printf("S3PutObject.Key Value: %v", s3PutObject.Key)
	fmt.Println("")

	uploadFile, err := s3PutObject.Body.Read([]byte("some-string-of-bytes"))
	if err != nil {
		log.Printf("error: %v", err)
		// return nil
	}

	fmt.Printf("s3PutObject.Body Type: %T\n\nValue: %v", uploadFile, uploadFile)
	fmt.Println("")
	fmt.Println("")
}

// TODO:
//     1. Create UploadObject struct
//     2. UploadObject.FileBytes == []byte("some-string-of-bytes")

//  --------------------------------------------------------------------------------

//  ########################
//  # Gatecheck AWS Config #
//  ########################

// func config.LoadDefaultConfig(ctx context.Context, optFns ...func(*config.LoadOptions) error) (cfg aws.Config, err error)
//
// LoadDefaultConfig reads the SDK's default external configurations, and populates an AWS Config with the values from the external configurations.
//
// An optional variadic set of additional Config values can be provided as input that will be prepended to the configs slice. Use this to add custom configuration. The custom configurations must satisfy the respective providers for their data or the custom data will be ignored by the resolvers and config loaders.
//
// 	cfg, err := config.LoadDefaultConfig( context.TODO(),
// 	   WithSharedConfigProfile("test-profile"),
// 	)
// 	if err != nil {
// 	   panic(fmt.Sprintf("failed loading config, %v", err))
// 	}
//
// The default configuration sources are: \* Environment Variables \* Shared Configuration and Shared Credentials files.

//  --------------------------------------------------------------------------------

// func config.LoadDefaultConfig(ctx context.Context, optFns ...func(*config.LoadOptions) error) (cfg aws.Config, err error)
//
// LoadDefaultConfig reads the SDK's default external configurations, and populates an AWS Config with the values from the external configurations.
//
// An optional variadic set of additional Config values can be provided as input that will be prepended to the configs slice. Use this to add custom configuration. The custom configurations must satisfy the respective providers for their data or the custom data will be ignored by the resolvers and config loaders.
//
// 	cfg, err := config.LoadDefaultConfig( context.TODO(),
// 	   WithSharedConfigProfile("test-profile"),
// 	)
// 	if err != nil {
// 	   panic(fmt.Sprintf("failed loading config, %v", err))
// 	}
//
// The default configuration sources are: \* Environment Variables \* Shared Configuration and Shared Credentials files.

//  --------------------------------------------------------------------------------

// Use unsafe package to string <-> byte conversion without copying
// func StringToBytes(s string) []byte {
// 	return unsafe.Slice(unsafe.StringData(s), len(s))
// }
//
// func BytesToString(b []byte) string {
// 	return unsafe.String(unsafe.SliceData(b), len(b))
// }

//  --------------------------------------------------------------------------------

//  ────────────────────────────────────────────────────────────────────────────────

//  #######################
//  # UploadObject Struct #
//  #######################

// type UploadObject struct {
// 	Bucket string
// 	Key    string
// 	Body   io.Reader
// }

//  ────────────────────────────────────────────────────────────────────────────────

//  ###########################
//  # S3PutObjectInput Struct #
//  ###########################

// var S3PutObjectInput s3.PutObjectInput

//  ────────────────────────────────────────────────────────────────────────────────

//  ################
//  # S3 Interface #
//  ################

// 1: Define S3 interface
// type S3 interface {
// 	//
// 	// 1: Define S3 interface Upload method
// 	//
// 	Upload()
// }

// 2: Define S3 interface implementation as Uploader struct with attributes
// type Uploader struct {
// 	S3PutObjectInput s3.PutObjectInput // GOOD: main.go
// 	// Bucket string // GOOD: main.go
// }

// 3: Define S3 interface implementation of Upload() method using Uploader struct with attributes
// func (u *Uploader) Upload() {
// 	// var err error
// 	// if err != nil {
// 	// 	log.Printf("error: %v", err)
// 	// 	return err
// 	// }
// 	// return nil
// 	log.Printf("returned Uploader Upload(), u *Uploader: %v\n\n", u)
// 	// return
// }

// 4: Define DoUpload() function which implements S3 interface making S3 interface methods Upload() and struct key:values available.
// Using interfaces to pass in structs makes mocking unit-tests much easier.
// func DoUpload(s S3) {
// 	fmt.Println("The S3 interface gives: ", s.Upload())
// }

//  ────────────────────────────────────────────────────────────────────────────────

//  ######################
//  # S3 Service Helpers #
//  ######################

// type Service struct {
// 	S3PutObjectInput s3.PutObjectInput
// }
//
// type ServiceBuilder struct {
// 	s3PutObjectInput *s3.PutObjectInput
// }
//
// func (b *ServiceBuilder) S3PutObjectInput(s3PutObjectInput s3.PutObjectInput) *ServiceBuilder {
// 	b.s3PutObjectInput = &s3PutObjectInput
//
// 	return b
// }
//
// func (b *ServiceBuilder) Build() (Service, error) {
// 	service := Service{}
//
// 	service.S3PutObjectInput = *b.s3PutObjectInput
//
// 	return service, nil
// }

//  ────────────────────────────────────────────────────────────────────────────────

// // UploadObject struct holds the values specific to each file upload.
// type UploadObject struct {
// 	Key  string
// 	File io.Reader
// }
//
// // key is an unexported type for keys defined in this package.
// // This prevents collisions with keys defined in other packages.
// type key int
//
// // serviceKey is the key for service.Service values in Contexts. It is
// // unexported; clients use service.NewContext and service.FromContext
// // instead of using this key directly.
// var serviceKey key
//
// // NewContext returns a new Context that carries value s.
// func NewContext(ctx context.Context, s *Service) context.Context {
// 	return context.WithValue(ctx, serviceKey, s)
// }
//
// // FromContext returns the Service value stored in ctx, if any.
// func FromContext(ctx context.Context) (Service, bool) {
// 	s, ok := ctx.Value(serviceKey).(Service)
// 	return s, ok
// }
//
// //  ────────────────────────────────────────────────────────────────────────────────
//
// // Service is the type of value stored in the Contexts.
// // Service can be used to export scans to AWS S3.
// type Service interface {
// 	Export(ctx context.Context, r io.Reader, uploadObject UploadObject) error
// 	// export(ctx context.Context, r io.Reader, uploadObject UploadObject) error
// }
//
// type ServiceImpl struct {
// 	Client          *http.Client
// 	Manager         *manager.Uploader
// 	Input           *s3.PutObjectInput
// 	BackoffDuration time.Duration // The interval for the exponential back off retry
// 	Retry           int
// 	Profile         string
// 	Bucket          string
// 	Service         Service
// }
//
// func NewService(client *http.Client, manager *manager.Uploader, input *s3.PutObjectInput, profile string, bucket string, service Service) Service {
// 	return &ServiceImpl{
// 		Client:          client,
// 		Manager:         manager,
// 		Input:           input,
// 		BackoffDuration: time.Second,
// 		Retry:           3,
// 		Profile:         profile,
// 		Bucket:          bucket,
// 		Service:         service,
// 	}
// }
//
// func (s *ServiceImpl) Export(ctx context.Context, r io.Reader, uploadObject UploadObject) error {
// 	c := make(chan error)
//
// 	go func() {
// 		var err error
// 		for i := 0; i < s.Retry; i++ {
// 			err = s.export(ctx, r, uploadObject)
// 			if err == nil {
// 				close(c)
// 				return
// 			}
// 			// Sleep for 2 ^ backoff, seconds
// 			sleepFor := time.Duration(int64(math.Pow(2, float64(i)))) * s.BackoffDuration
// 			log.Printf("Export Attempt %d / %d, will Retrying after %s. Error: %v\n", i+1, s.Retry,
// 				sleepFor.String(), err)
// 			time.Sleep(sleepFor)
// 		}
// 		c <- err
// 	}()
//
// 	for {
// 		select {
// 		case err, ok := <-c:
// 			if !ok {
// 				return nil
// 			}
// 			return err
// 		case <-ctx.Done():
// 			return ctx.Err()
// 		}
// 	}
// }
//
// func (s *ServiceImpl) export(ctx context.Context, r io.Reader, uploadObject UploadObject) error {
// 	fmt.Println("")
// 	fmt.Println("────────────────────────── *ServiceImpl ─────────────────────────")
// 	fmt.Println("")
// 	fmt.Println("────────────────────────── s.Input ─────────────────────────")
// 	fmt.Println("")
//
// 	log.Printf("DEBUGPRINT[1]: s3.go:109: s=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", s, s.Input.Bucket)
//
// 	fmt.Println("")
// 	fmt.Println("────────────────────────── ctx context.Context ─────────────────────────")
// 	fmt.Println("")
// 	log.Printf("DEBUGPRINT[2]: s3.go:109: ctx=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", ctx, ctx)
//
// 	fmt.Println("")
// 	fmt.Println("────────────────────────── uploadObject UploadObject ─────────────────────────")
// 	fmt.Println("")
// 	log.Printf("DEBUGPRINT[3]: s3.go:109: uploadObject=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", uploadObject, uploadObject)
//
// 	res, err := s.Manager.Upload(ctx, putObjectInput{
// 		Bucket: s.Bucket,
// 		Key:    uploadObject.Key,
// 		Body:   r,
// 	})
// 	if err != nil {
// 		log.Printf("error: %v", err)
// 		return err
// 	}
// 	log.Printf("DEBUGPRINT[4]: s3.go:130: res=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", res)
//
// 	// res, err := uploader.Upload(ctx, &putObjectInput{
// 	// 	Bucket: "bucket",
// 	// 	Key:    "key",
// 	// 	Body:   bytes.NewReader([]byte("some-file-contents")),
// 	// }, func(u uploader) {
// 	// 	u.PartSize = 5 * 1024 * 1024
// 	// })
// 	// if err != nil {
// 	// 	log.Printf("error: %v", err)
// 	// 	return nil
// 	// }
// 	//
//
// 	// res, err := s.Manager.Upload(ctx, &s3.PutObjectInput{
// 	// 	Bucket: &s.Bucket,
// 	// 	Key:    &uploadObject.Key,
// 	// 	Body:   r,
// 	// }, func(u *manager.Uploader) {
// 	// 	u.PartSize = 5 * 1024 * 1024
// 	// })
// 	//
// 	// fmt.Println("")
// 	// fmt.Println("────────────────────────── /END Gatecheck S3 Export Service ─────────────────────────")
// 	// fmt.Println("")
// 	//
// 	// if err != nil {
// 	// 	log.Printf("error: %v", err)
// 	// 	return err
// 	// }
//
// 	return nil
// }
//
// // func (s Service) postScan(r io.Reader, scanType ScanType, e engagement) error {
// // 	url := s.url + "/api/v2/import-scan/"
// // 	// After getting an engagement, post the scan using a multipart form
// // 	payload := &bytes.Buffer{}
// // 	writer := multipart.NewWriter(payload)
// // 	_ = writer.WriteField("engagement", strconv.Itoa(e.Id))
// // 	_ = writer.WriteField("scan_type", string(scanType))
// //
// // 	filePart, _ := writer.CreateFormFile("file", fmt.Sprintf("%s report.json", scanType))
// //
// // 	// Copy the file content to the filePart
// // 	if _, err := io.Copy(filePart, r); err != nil {
// // 		return fmt.Errorf("Defect Dojo, can't write file to form %w\n", err)
// // 	}
// //
// // 	contentType := writer.FormDataContentType()
// // 	_ = writer.Close()
// //
// // 	req, _ := http.NewRequest(http.MethodPost, url, payload)
// // 	req.Header.Set("Content-Type", contentType)
// // 	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))
// //
// // 	res, err := s.client.Do(req)
// // 	if err != nil {
// // 		return err
// // 	}
// //
// // 	if res.StatusCode != http.StatusCreated {
// // 		msg, _ := io.ReadAll(res.Body)
// // 		return fmt.Errorf("%w: POST '%s' unexpected response code %d msg: %s",
// // 			RequestError, url, res.StatusCode, msg)
// // 	}
// //
// // 	return nil
// // }
// //
// // func (s Service) postJSON(url string, reqBody io.Reader) (resBody io.ReadCloser, err error) {
// // 	req, _ := http.NewRequest(http.MethodPost, url, reqBody)
// // 	req.Header.Set("Content-Type", contentTypeJSON)
// // 	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))
// //
// // 	res, err := s.client.Do(req)
// // 	if err != nil {
// // 		return nil, err
// // 	}
// //
// // 	if res.StatusCode != http.StatusCreated {
// // 		msg, _ := io.ReadAll(res.Body)
// // 		return nil, fmt.Errorf("%w: GET '%s' unexpected response code %d: msg: %s",
// // 			RequestError, url, res.StatusCode, string(msg))
// // 	}
// // 	return res.Body, nil
// // }
//
// //  ────────────────────────────────────────────────────────────────────────────────
//
// // ToS3 is the entrypoint function that loads the AWS Config, constructs the Client Service,
// // invokes the API Operation, and builds a new *s3.Client.
// // builds a new *s3.Client.
// // func ToS3(ctx context.Context, i awsS3.PutObjectInput) error {
// // 	fmt.Println("──────────── ClientFor(ctx context.Context) *s3.Client ──────────────")
// // 	fmt.Println("")
// //
// // 	// Loads the AWS Config
// // 	cfg, err := config.LoadDefaultConfig(ctx)
// // 	if err != nil {
// // 		return err
// // 	}
// //
// // 	// Constructs the Client Service
// // 	client := s3.NewFromConfig(cfg)
// //
// // 	uploader := manager.NewUploader(client)
// //
// // 	// Invokes the API Operation
// // 	output, err := uploader.Upload(ctx, &awsS3.PutObjectInput{
// // 		Bucket: i.Bucket,
// // 		Key:    i.Key,
// // 		Body:   i.Body,
// // 	})
// // 	if err != nil {
// // 		return err
// // 	}
// //
// // 	fmt.Printf("File upload type: %T\n\nvalue: %v\n\n", output, output)
// // 	return nil
// // }
//
// //  ────────────────────────────────────────────────────────────────────────────────
