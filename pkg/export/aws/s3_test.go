// package aws unit-tests for `gatecheck export aws` module
package aws

import (
	"log"
	"strings"
	"testing"
)

//  ########################
//  # Gatecheck AWS Config #
//  ########################

// type T struct {
// 	common
// 	isEnvSet bool
// 	context  *testContext // For running tests and subtests.
// }
//
// func (*testing.T).Deadline() (deadline time.Time, ok bool)
// func (*testing.T).Parallel()
// func (*testing.T).Run(name string, f func(t *testing.T)) bool
// func (*testing.T).Setenv(key string, value string)

// T is a type passed to Test functions to manage test state and support formatted test logs.

// A test ends when its Test function returns or calls any of the methods FailNow, Fatal, Fatalf, SkipNow, Skip, or
// Skipf. Those methods, as well as the Parallel method, must be called only from the goroutine running the Test
// function.

// The other reporting methods, such as the variations of Log and Error, may be called simultaneously from multiple
// goroutines.

type mockDDEngagement struct {
	ProductTypeName string
	ProductName     string
	Name            string
}

type mockUpload struct {
	Key  string
	File []byte
}

type mockService struct {
	Profile string
	Bucket  string
}

// func (mockS3PutObject *mockS3PutObject) S3PutObjectInputs() {
// 	// mock implementation of Inputs
// 	log.Printf("DEBUGPRINT[2]: s3_test.go:44: mockS3PutObject=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", mockS3PutObject, mockS3PutObject)
// }

func TestConfigInputs(t *testing.T) {
	// setupInputs()
	// defer teardownInputs()
	t.Run("bad-AWS-profile", func(t *testing.T) {
		setupInputs(strings.Split(t.Name(), "/")[1])
		defer teardownInputs(t.Name())

		t.Logf("Current Test: %v\n\n", t.Name())
	})

	t.Run("good-AWS-profile", func(t *testing.T) {
		t.Logf("Current Test: %v\n\n", t.Name())
	})
}

func setupInputs(v ...any) {
	log.Println("setup inputs")
	log.Println("")

	log.Printf("setup args: type: %T\n\nvalue: %v", v, v)

	// m := mockS3PutObject{}
	// log.Printf("DEBUGPRINT[3]: s3_test.go:66: m=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", m, m)
}

func teardownInputs(v ...any) {
	log.Println("teardown inputs")
	log.Println("")

	log.Printf("teardown args: type: %T\n\nvalue: %v", v, v)

	// m := mockS3PutObject{}
	// log.Printf("DEBUGPRINT[3]: s3_test.go:66: m=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", m, m)
}

//  --------------------------------------------------------------------------------

//  ────────────────────────────────────────────────────────────────────────────────

// func TestService_export(t *testing.T) {
// 	type fields struct {
// 		Client          *http.Client
// 		Manager         *manager.Uploader
// 		Params          *s3.PutObjectInput
// 		BackoffDuration time.Duration
// 		Retry           int
// 	}
// 	type args struct {
// 		ctx          context.Context
// 		r            io.Reader
// 		uploadObject UploadObject
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 		{
// 			name: "good-upload",
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			s := Service{
// 				Client:          tt.fields.Client,
// 				Manager:         tt.fields.Manager,
// 				Params:          tt.fields.Params,
// 				BackoffDuration: tt.fields.BackoffDuration,
// 				Retry:           tt.fields.Retry,
// 			}
// 			if err := s.export(tt.args.ctx, tt.args.r, tt.args.uploadObject); (err != nil) != tt.wantErr {
// 				t.Errorf("Service.export() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

// func Test_export(t *testing.T) {
// 	// t.Run("bad-productType", func(t *testing.T) {
// 	// 	serverRes := paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}}
// 	// 	server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
// 	// 	service := NewService(server.Client(), "", server.URL)
// 	// 	server.Close()
// 	// 	if err := service.export(bytes.NewBufferString("a"), EngagementQuery{}, Grype); err == nil {
// 	// 		t.Fatal("Expected error for bad product type query")
// 	// 	}
// 	// })
// 	//
// 	// t.Run("bad-product", func(t *testing.T) {
// 	// 	routeTable := map[string]any{
// 	// 		"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
// 	// 	}
// 	//
// 	// 	server := httptest.NewServer(mapHandler(routeTable))
// 	// 	service := NewService(server.Client(), "", server.URL)
// 	// 	if err := service.export(bytes.NewBufferString("a"), EngagementQuery{ProductTypeName: "A"}, Grype); err == nil {
// 	// 		t.Fatal("Expected error for bad product query")
// 	// 	}
// 	// })
// 	//
// 	// t.Run("bad-engagement", func(t *testing.T) {
// 	// 	routeTable := map[string]any{
// 	// 		"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
// 	// 		"/api/v2/products/":      paginatedResponse[product]{Results: []product{{Name: "some product", Id: 5, ProdType: 2}}},
// 	// 	}
// 	//
// 	// 	eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product"}
// 	//
// 	// 	server := httptest.NewServer(mapHandler(routeTable))
// 	// 	service := NewService(server.Client(), "", server.URL)
// 	// 	if err := service.export(bytes.NewBufferString("a"), eq, Grype); err == nil {
// 	// 		t.Fatal("Expected error for bad product query")
// 	// 	}
// 	// })
//
// 	t.Run("success", func(t *testing.T) {
// 		// routeTable := map[string]any{
// 		// 	"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
// 		// 	"/api/v2/products/":      paginatedResponse[product]{Results: []product{{Name: "some product", Id: 5, ProdType: 2}}},
// 		// 	"/api/v2/engagements/":   paginatedResponse[engagement]{Results: []engagement{{Name: "some engagement", Id: 7, Product: 5}}},
// 		// 	"/api/v2/import-scan/":   TestStruct{A: "Good"},
// 		// }
//
// 		uo := UploadObject{
// 			Key:  "some-key",
// 			File: bytes.NewReader([]byte("some-file-contents")),
// 		}
// 		log.Printf("DEBUGPRINT[3]: s3_test.go:64: uo=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", uo, uo)
//
// 		// eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product", Name: "some engagement"}
// 		//
// 		// server := httptest.NewServer(mapHandler(routeTable))
// 		// service := NewService(server.Client(), "", server.URL)
// 		// if err := service.export(bytes.NewBufferString("a"), eq, Grype); err != nil {
// 		// 	t.Fatal(err)
// 		// }
// 	})
// }

//  ────────────────────────────────────────────────────────────────────────────────

// TestService_Export function
// func TestService_Export(t *testing.T) {
// 	type fields struct {
// 		Client          *http.Client
// 		Manager         *manager.Uploader
// 		Params          *s3.PutObjectInput
// 		BackoffDuration time.Duration
// 		Retry           int
// 	}
// 	type args struct {
// 		ctx          context.Context
// 		r            io.Reader
// 		uploadObject UploadObject
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			s := Service{
// 				Client:          tt.fields.Client,
// 				Manager:         tt.fields.Manager,
// 				Params:          tt.fields.Params,
// 				BackoffDuration: tt.fields.BackoffDuration,
// 				Retry:           tt.fields.Retry,
// 			}
// 			if err := s.Export(tt.args.ctx, tt.args.r, tt.args.uploadObject); (err != nil) != tt.wantErr {
// 				t.Errorf("Service.Export() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

//  ────────────────────────────────────────────────────────────────────────────────

// func TestNewService(t *testing.T) {
// 	// log.Printf("DEBUGPRINT[1]: s3_test.go:62: t=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", t, t)
//
// 	// => value=&{
// 	//      common:{
// 	//          mu:{
// 	//              w:{
// 	//                  state:0
// 	//                  sema:0
// 	//              }
// 	//              writerSem:0
// 	//              readerSem:0
// 	//              readerCount:{
// 	//                  _:{}
// 	//                  v:0
// 	//              }
// 	//              readerWait:{
// 	//                  _:{}
// 	//                  v:0
// 	//              }
// 	//          }
// 	//          output:[]
// 	//          w:{
// 	//              c:0xc0000831e0
// 	//          }
// 	//          ran:false
// 	//          failed:false
// 	//          skipped:false
// 	//          done:false
// 	//          helperPCs:map[]
// 	//          helperNames:map[]
// 	//          cleanups:[]
// 	//          cleanupName:
// 	//          cleanupPc:[]
// 	//          finished:false
// 	//          inFuzzFn:false
// 	//          chatty:0xc0000a1650
// 	//          bench:false
// 	//          hasSub:{
// 	//              _:{}
// 	//              v:0
// 	//          }
// 	//          cleanupStarted:{
// 	//              _:
// 	//                  {}
// 	//                  v:0
// 	//              }
// 	//              raceErrors:0
// 	//              runner:testing.tRunner
// 	//              isParallel:false
// 	//              parent:0xc000083040
// 	//              level:1
// 	//              creator:[
// 	//                  17863877 17851467 17863593 17857818 18522917 17006695 17211521
// 	//              ]
// 	//              name:TestNewService
// 	//              start:{
// 	//                  wall:13906666721746075720
// 	//                  ext:1207877
// 	//                  loc:0x13afb20
// 	//              }
// 	//              duration:0
// 	//              barrier:0xc000096600
// 	//              signal:0xc00008c0e0
// 	//              sub:[]
// 	//              tempDirMu:{
// 	//                  state:0
// 	//                  sema:0
// 	//              }
// 	//              tempDir:
// 	//              tempDirErr:<nil>
// 	//              tempDirSeq:0
// 	//          }
// 	//          isEnvSet:false
// 	//          context:0xc000094370
// 	//      }
//
// 	type args struct {
// 		client  *http.Client
// 		manager *manager.Uploader
// 		params  *s3.PutObjectInput
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want Service
// 	}{
// 		// TODO: Add test cases.
// 		{
// 			name: "My-Test-Service",
// 			args: args{},
// 			want: Service{},
// 		},
// 	}
// 	for _, tt := range tests {
// 		// name: "My-Test-Service"
// 		if tt.name == "My-Test-Service" {
// 			log.Printf("DEBUGPRINT[2]: s3_test.go:159: tt.name=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", tt.name, tt.name)
// 			log.Printf("DEBUGPRINT[3]: s3_test.go:161: tt=>↲\n\n=> type=%T\n\n=> value=%+v\n\n", tt, tt)
// 			t.Run(tt.name, func(t *testing.T) {
// 				if got := NewService(tt.args.client, tt.args.manager, tt.args.params); !reflect.DeepEqual(got, tt.want) {
// 					t.Errorf("NewService() = %v, want %v", got, tt.want)
// 				}
// 			})
// 		}
//
// 		// default generated test
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := NewService(tt.args.client, tt.args.manager, tt.args.params); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("NewService() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

//  ────────────────────────────────────────────────────────────────────────────────

// func TestFromContext(t *testing.T) {
// 	type args struct {
// 		ctx context.Context
// 	}
// 	tests := []struct {
// 		name  string
// 		args  args
// 		want  *Service
// 		want1 bool
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, got1 := FromContext(tt.args.ctx)
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("FromContext() got = %v, want %v", got, tt.want)
// 			}
// 			if got1 != tt.want1 {
// 				t.Errorf("FromContext() got1 = %v, want %v", got1, tt.want1)
// 			}
// 		})
// 	}
// }

//  ────────────────────────────────────────────────────────────────────────────────

// func TestNewContext(t *testing.T) {
// 	type args struct {
// 		ctx context.Context
// 		s   *Service
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want context.Context
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := NewContext(tt.args.ctx, tt.args.s); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("NewContext() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

//  ────────────────────────────────────────────────────────────────────────────────

// func TestToS3(t *testing.T) {
// 	type args struct {
// 		ctx context.Context
// 		i   s3.PutObjectInput
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 		{
// 			name: "failed-upload",
// 			args: args{
// 				ctx: context.TODO(),
// 				i: s3.PutObjectInput{
// 					Bucket: aws.String("nonexistent-bucket"),
// 					Key:    aws.String("some-key"),
// 					Body:   bytes.NewReader([]byte("some-file-contents")),
// 				},
// 			},
// 			wantErr: true,
// 		},
// 		{
// 			name: "successful-upload",
// 			args: args{
// 				ctx: context.TODO(),
// 				i: s3.PutObjectInput{
// 					Bucket: aws.String(os.Getenv("AWS_BUCKET")),
// 					Key:    aws.String("some-key"),
// 					Body:   bytes.NewReader([]byte("some-file-contents")),
// 				},
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name: "failed-without-error-upload",
// 			args: args{
// 				ctx: context.TODO(),
// 				i: s3.PutObjectInput{
// 					Bucket: aws.String("nonexistent-bucket"),
// 					Key:    aws.String("some-key"),
// 					Body:   bytes.NewReader([]byte("")),
// 				},
// 			},
// 			wantErr: true,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if err := ToS3(tt.args.ctx, tt.args.i); (err != nil) != tt.wantErr {
// 				t.Errorf("ToS3() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

//  ────────────────────────────────────────────────────────────────────────────────

//  ────────────────────────────────────────────────────────────────────────────────
