// package s3_test contains the unit-test code for `gatecheck export s3`
package s3

import "testing"

func TestUploadObjectToS3(t *testing.T) {
	tests := []struct {
		name string
		// wantErr bool
	}{
		// TODO: Add test cases.
		// {"bad-upload", true},
		// {"good-upload", false},
		{"bad-upload"},
		{"good-upload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UploadObjectToS3()
			// if err := UploadObjectToS3(); (err != nil) != tt.wantErr {
			// 	t.Errorf("UploadObjectToS3() error = %v, wantErr %v", err, tt.wantErr)
			// }
		})
	}
}
