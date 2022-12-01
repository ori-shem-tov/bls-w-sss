package curvebls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"reflect"
	"testing"
)

func TestMessage_String(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want string
	}{
		{
			name: "nil message",
			msg:  nil,
			want: "",
		},
		{
			name: "empty message",
			msg:  Message{},
			want: "",
		},
		{
			name: "a message",
			msg:  Message("this a message"),
			want: "dGhpcyBhIG1lc3NhZ2U=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.msg.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMessage_hashToPoint(t *testing.T) {
	emptyMessagePoint := bls12381.G1Affine{
		X: fp.Element{9161281962972194788, 7959241047245594768, 7462352191568447521, 10227315852296200449, 17818847659122208288, 408687242435129147},
		Y: fp.Element{5909039643818949156, 18283888317092666484, 8024887215282213813, 2537223215759799723, 744832629309823391, 1301298213623031517},
	}
	aMessagePoint := bls12381.G1Affine{
		X: fp.Element{18237545818876946991, 6367951117227510020, 17252071404224050101, 17551160542812847998, 5521445008899046417, 624926158933272841},
		Y: fp.Element{3728281996398986615, 14989055214748379473, 17405445139708342865, 15734423453110465165, 13539857886949924714, 91380460356427188},
	}
	tests := []struct {
		name    string
		msg     Message
		want    bls12381.G1Affine
		wantErr bool
	}{
		{
			name:    "nil message",
			msg:     nil,
			want:    emptyMessagePoint,
			wantErr: false,
		},
		{
			name:    "empty message",
			msg:     Message{},
			want:    emptyMessagePoint,
			wantErr: false,
		},
		{
			name:    "a message",
			msg:     Message("this a message"),
			want:    aMessagePoint,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.msg.hashToPoint()
			if (err != nil) != tt.wantErr {
				t.Errorf("hashToPoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hashToPoint() got = %v, want %v", got, tt.want)
			}
		})
	}
}
