package curvebls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"reflect"
	"testing"
)

var (
	aPKPoint bls12381.G2Affine
)

func init() {
	_, err := aPKPoint.SetBytes([]byte{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212})
	if err != nil {
		// should never happen
		panic(err)
	}
}

func TestPublicKey_String(t *testing.T) {
	tests := []struct {
		name string
		pk   PublicKey
		want string
	}{
		{
			name: "zero signature",
			pk:   PublicKey{},
			want: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pk.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKey_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pk      PublicKey
		wantErr bool
	}{
		{
			name:    "empty pk",
			pk:      PublicKey{},
			wantErr: true,
		},
		{
			name:    "not in subgroup pk",
			pk:      PublicKey{1},
			wantErr: true,
		},
		{
			name:    "malformed buffer",
			pk:      PublicKey{23, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212},
			wantErr: true,
		},
		{
			name:    "a pk",
			pk:      PublicKey{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pk.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublicKey_Verify(t *testing.T) {
	type args struct {
		msg Message
		sig Signature
	}
	tests := []struct {
		name    string
		pk      PublicKey
		args    args
		wantErr bool
	}{
		{
			name:    "basic test",
			pk:      PublicKey{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212},
			args:    args{sig: Signature{133, 94, 59, 242, 47, 143, 66, 21, 203, 197, 47, 194, 74, 13, 167, 20, 138, 191, 77, 171, 192, 228, 233, 137, 201, 199, 220, 64, 169, 232, 226, 82, 124, 113, 220, 170, 136, 108, 122, 23, 180, 48, 37, 84, 33, 56, 73, 254}, msg: Message("a message")},
			wantErr: false,
		},
		{
			name:    "basic test2",
			pk:      PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255},
			args:    args{sig: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39}, msg: Message("a message")},
			wantErr: false,
		},
		{
			name:    "sig not in subgroup",
			pk:      PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255},
			args:    args{sig: Signature{1}, msg: Message("a message")},
			wantErr: true,
		},
		{
			name:    "pk not in subgroup",
			pk:      PublicKey{1},
			args:    args{sig: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39}, msg: Message("a message")},
			wantErr: true,
		},
		{
			name:    "zero pk",
			pk:      PublicKey{},
			args:    args{sig: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39}, msg: Message("a message")},
			wantErr: true,
		},
		{
			name:    "invalid signature (that is in subgroup)",
			pk:      PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255},
			args:    args{sig: Signature{133, 94, 59, 242, 47, 143, 66, 21, 203, 197, 47, 194, 74, 13, 167, 20, 138, 191, 77, 171, 192, 228, 233, 137, 201, 199, 220, 64, 169, 232, 226, 82, 124, 113, 220, 170, 136, 108, 122, 23, 180, 48, 37, 84, 33, 56, 73, 254}, msg: Message("a message")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pk.Verify(tt.args.msg, tt.args.sig); (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublicKey_coreVerify(t *testing.T) {
	type args struct {
		msg Message
		sig Signature
	}
	tests := []struct {
		name    string
		pk      PublicKey
		args    args
		wantErr bool
	}{
		{
			name:    "basic test",
			pk:      PublicKey{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212},
			args:    args{sig: Signature{133, 94, 59, 242, 47, 143, 66, 21, 203, 197, 47, 194, 74, 13, 167, 20, 138, 191, 77, 171, 192, 228, 233, 137, 201, 199, 220, 64, 169, 232, 226, 82, 124, 113, 220, 170, 136, 108, 122, 23, 180, 48, 37, 84, 33, 56, 73, 254}, msg: Message("a message")},
			wantErr: false,
		},
		{
			name:    "basic test2",
			pk:      PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255},
			args:    args{sig: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39}, msg: Message("a message")},
			wantErr: false,
		},
		{
			name:    "sig not in subgroup",
			pk:      PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255},
			args:    args{sig: Signature{1}, msg: Message("a message")},
			wantErr: true,
		},
		{
			name:    "pk not in subgroup",
			pk:      PublicKey{1},
			args:    args{sig: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39}, msg: Message("a message")},
			wantErr: true,
		},
		{
			name:    "zero pk",
			pk:      PublicKey{},
			args:    args{sig: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39}, msg: Message("a message")},
			wantErr: true,
		},
		{
			name:    "invalid signature (that is in subgroup)",
			pk:      PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255},
			args:    args{sig: Signature{5, 94, 59, 242, 47, 143, 66, 21, 203, 197, 47, 194, 74, 13, 167, 20, 138, 191, 77, 171, 192, 228, 233, 137, 201, 199, 220, 64, 169, 232, 226, 82, 124, 113, 220, 170, 136, 108, 122, 23, 180, 48, 37, 84, 33, 56, 73, 254}, msg: Message("a message")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.pk.coreVerify(tt.args.msg, tt.args.sig); (err != nil) != tt.wantErr {
				t.Errorf("coreVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublicKey_pubkeyToPoint(t *testing.T) {
	tests := []struct {
		name    string
		pk      PublicKey
		want    bls12381.G2Affine
		wantErr bool
	}{
		{
			name:    "empty pk",
			pk:      PublicKey{},
			want:    bls12381.G2Affine{},
			wantErr: true,
		},
		{
			name:    "not in subgroup pk",
			pk:      PublicKey{1},
			want:    bls12381.G2Affine{},
			wantErr: true,
		},
		{
			name:    "a pk",
			pk:      PublicKey{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212},
			want:    aPKPoint,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.pk.pubkeyToPoint()
			if (err != nil) != tt.wantErr {
				t.Errorf("pubkeyToPoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pubkeyToPoint() got = %v, want %v", got.Bytes(), tt.want)
			}
		})
	}
}

func TestPublicKey_pubkeyToPointWithValidate(t *testing.T) {
	tests := []struct {
		name    string
		pk      PublicKey
		want    bls12381.G2Affine
		wantErr bool
	}{
		{
			name:    "zero pk",
			pk:      PublicKey{},
			want:    bls12381.G2Affine{},
			wantErr: true,
		},
		{
			name:    "not in subgroup pk",
			pk:      PublicKey{1},
			want:    bls12381.G2Affine{},
			wantErr: true,
		},
		{
			name:    "a pk",
			pk:      PublicKey{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212},
			want:    aPKPoint,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.pk.pubkeyToPointWithValidate()
			if (err != nil) != tt.wantErr {
				t.Errorf("pubkeyToPointWithValidate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pubkeyToPointWithValidate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
