package curvebls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"reflect"
	"testing"
)

func TestSignature_String(t *testing.T) {
	tests := []struct {
		name string
		sig  Signature
		want string
	}{
		{
			name: "zero signature",
			sig:  Signature{},
			want: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sig.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignature_sigToPoint(t *testing.T) {
	tests := []struct {
		name    string
		sig     Signature
		want    bls12381.G1Affine
		wantErr bool
	}{
		{
			name:    "zero signature",
			sig:     Signature{},
			want:    bls12381.G1Affine{},
			wantErr: false,
		},
		{
			name:    "not in subgroup",
			sig:     Signature{1},
			want:    bls12381.G1Affine{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sig.sigToPoint()
			if (err != nil) != tt.wantErr {
				t.Errorf("sigToPoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sigToPoint() got = %v, want %v", got, tt.want)
			}
		})
	}
}
