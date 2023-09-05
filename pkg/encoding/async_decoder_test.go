package encoding

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestAsyncDecoder(t *testing.T) {
	t.Run("success-decode-from", func(t *testing.T) {
		heroBuf := new(bytes.Buffer)
		cityBuf := new(bytes.Buffer)
		wantHero := &Hero{Name: "Tony Stark", Alias: "Iron Man", Universe: "marvel"}
		wantCity := &City{Name: "Austin", Population: 24, StateCode: "TX"}
		_ = json.NewEncoder(heroBuf).Encode(wantHero)
		obj, err := NewAsyncDecoder().WithDecoders(newHeroDecoder(), newStateDecoder()).DecodeFrom(heroBuf)
		if err != nil {
			t.Fatal(err)
		}
		hero, ok := obj.(*Hero)
		if !ok {
			t.Fatalf("Got Type %T", obj)
		}
		if hero.Name != wantHero.Name {
			t.Fatalf("want: %v got: %v", wantHero, hero)
		}

		_ = json.NewEncoder(cityBuf).Encode(wantCity)
		obj, err = NewAsyncDecoder().WithDecoders(newHeroDecoder(), newStateDecoder()).DecodeFrom(cityBuf)
		if err != nil {
			t.Fatal(err)
		}
		city, ok := obj.(*City)
		if !ok {
			t.Fatalf("Got Type %T", obj)
		}
		if city.Name != wantCity.Name {
			t.Fatalf("want: %v got: %v", wantCity, city)
		}
	})

	t.Run("bad-reader", func(t *testing.T) {
		_, err := NewAsyncDecoder().DecodeFrom(&badReader{})
		if !errors.Is(err, ErrIO) {
			t.Fatalf("want: %v got: %v", ErrIO, err)
		}
		_, err = NewAsyncDecoder(&badDecoder{}).DecodeFrom(strings.NewReader("Content"))
		if !errors.Is(err, ErrIO) {
			t.Fatalf("want: %v got: %v", ErrIO, err)
		}
	})

	t.Run("no-decoders", func(t *testing.T) {
		_, err := NewAsyncDecoder().DecodeFrom(strings.NewReader("Content"))
		if !errors.Is(err, ErrEncoding) {
			t.Fatalf("want: %v got: %v", ErrEncoding, err)
		}

		if NewAsyncDecoder().FileType() != "?" {
			t.Fatal()
		}
	})

	t.Run("generic", func(t *testing.T) {

		decoder := NewAsyncDecoder(newHeroDecoder())
		_, err := decoder.DecodeFrom(strings.NewReader("Content"))
		if !errors.Is(err, ErrEncoding) {
			t.Fatalf("want: %v got: %v", ErrEncoding, err)
		}
		if decoder.FileType() != "Generic" {
			t.Fatalf("want: %v got: %v", "Generic", decoder.FileType())
		}
	})

}

type badReader struct{}

func (r *badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("Mock Read error")
}

type badDecoder struct{}

func (d *badDecoder) Write(_ []byte) (int, error) {
	return 0, errors.New("Mock Read error")
}
func (d *badDecoder) Decode() (any, error) {
	return nil, nil
}
func (d *badDecoder) DecodeFrom(_ io.Reader) (any, error) {
	return nil, nil
}
func (d *badDecoder) FileType() string {
	return "bad decoder"
}

type Hero struct {
	Name     string
	Alias    string
	Universe string
}

func checkHero(h *Hero) error {
	if h.Universe != "marvel" && h.Universe != "dc" {
		return ErrFailedCheck
	}
	return nil
}

func newHeroDecoder() *JSONWriterDecoder[Hero] {
	return NewJSONWriterDecoder[Hero]("Hero", checkHero)
}

type City struct {
	Name       string
	Population int
	StateCode  string
}

func checkState(c *City) error {
	if len(c.StateCode) != 2 {
		return ErrFailedCheck
	}
	return nil
}

func newStateDecoder() *JSONWriterDecoder[City] {
	return NewJSONWriterDecoder[City]("City", checkState)
}
