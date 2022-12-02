package curvebls12381

import (
	"math/big"
	"reflect"
	"testing"
)

func TestKeyGen(t *testing.T) {
	tests := []struct {
		name    string
		want    PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KeyGen()
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyGen() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_PublicKey(t *testing.T) {
	basicPK := PublicKey{183, 15, 132, 42, 44, 133, 97, 77, 136, 206, 39, 112, 0, 209, 47, 8, 191, 42, 179, 128, 55, 230, 155, 105, 153, 2, 183, 135, 50, 210, 184, 216, 52, 249, 123, 10, 2, 5, 241, 48, 229, 97, 93, 23, 138, 46, 228, 201, 11, 203, 102, 185, 21, 25, 157, 214, 30, 166, 125, 14, 181, 90, 44, 169, 152, 203, 63, 182, 44, 202, 115, 72, 176, 80, 194, 248, 251, 65, 29, 205, 121, 146, 21, 103, 208, 29, 193, 103, 222, 0, 35, 112, 178, 19, 1, 212}
	basicPK2 := PublicKey{176, 63, 206, 127, 50, 69, 176, 147, 235, 97, 76, 181, 157, 173, 177, 119, 243, 70, 43, 22, 34, 4, 247, 133, 221, 169, 11, 220, 27, 90, 52, 191, 147, 173, 27, 65, 40, 155, 234, 74, 154, 148, 72, 135, 151, 76, 253, 162, 24, 148, 145, 69, 73, 162, 197, 44, 242, 120, 10, 7, 202, 6, 219, 145, 71, 191, 123, 106, 140, 163, 188, 84, 145, 90, 107, 49, 115, 152, 107, 228, 20, 72, 80, 13, 47, 16, 59, 107, 81, 197, 157, 113, 203, 143, 252, 255}

	tests := []struct {
		name string
		sk   PrivateKey
		want PublicKey
	}{
		{
			name: "basic test",
			sk:   PrivateKey{1},
			want: basicPK,
		},
		{
			name: "basic test2",
			sk:   PrivateKey{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
			want: basicPK2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sk.PublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_Sign(t *testing.T) {
	type args struct {
		msg Message
	}
	tests := []struct {
		name    string
		sk      PrivateKey
		args    args
		want    Signature
		wantErr bool
	}{
		{
			name: "basic test",
			sk:   PrivateKey{1},
			args: args{msg: Message("a message")},
			want: Signature{133, 94, 59, 242, 47, 143, 66, 21, 203, 197, 47, 194, 74, 13, 167, 20, 138, 191, 77, 171, 192, 228, 233, 137, 201, 199, 220, 64, 169, 232, 226, 82, 124, 113, 220, 170, 136, 108, 122, 23, 180, 48, 37, 84, 33, 56, 73, 254},
		},
		{
			name: "basic test2",
			sk:   PrivateKey{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
			args: args{msg: Message("a message")},
			want: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sk.Sign(tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_String(t *testing.T) {
	tests := []struct {
		name string
		sk   PrivateKey
		want string
	}{
		{
			name: "zero sk",
			sk:   PrivateKey{},
			want: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sk.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_coreSign(t *testing.T) {
	type args struct {
		msg Message
	}
	tests := []struct {
		name    string
		sk      PrivateKey
		args    args
		want    Signature
		wantErr bool
	}{
		{
			name: "basic test",
			sk:   PrivateKey{1},
			args: args{msg: Message("a message")},
			want: Signature{133, 94, 59, 242, 47, 143, 66, 21, 203, 197, 47, 194, 74, 13, 167, 20, 138, 191, 77, 171, 192, 228, 233, 137, 201, 199, 220, 64, 169, 232, 226, 82, 124, 113, 220, 170, 136, 108, 122, 23, 180, 48, 37, 84, 33, 56, 73, 254},
		},
		{
			name: "basic test2",
			sk:   PrivateKey{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
			args: args{msg: Message("a message")},
			want: Signature{128, 43, 38, 10, 78, 67, 146, 228, 15, 53, 227, 221, 77, 90, 243, 106, 111, 175, 69, 42, 18, 223, 183, 180, 112, 3, 135, 45, 246, 146, 13, 4, 101, 150, 229, 138, 192, 247, 191, 54, 246, 49, 187, 227, 125, 234, 58, 39},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sk.coreSign(tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("coreSign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("coreSign() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_toBigInt(t *testing.T) {
	var basic, basic2 big.Int
	basic.SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	basic2.SetBytes([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	tests := []struct {
		name string
		sk   PrivateKey
		want big.Int
	}{
		{
			name: "basic test",
			sk:   PrivateKey{1},
			want: basic,
		},
		{
			name: "basic test2",
			sk:   PrivateKey{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
			want: basic2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sk.toBigInt(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toBigInt() = %v, want %v", got, tt.want)
			}
		})
	}
}
