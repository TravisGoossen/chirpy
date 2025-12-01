package auth

import (
	"testing"
)

func TestHash(t *testing.T) {
	cases := []struct {
		pass  string
		match bool
	}{
		{
			pass:  "password",
			match: true,
		},
		{
			pass:  "sUPPerPas$$$w0RD!here!!",
			match: true,
		},
		{
			pass:  "1230982130981230918409280918502980398102983",
			match: true,
		},
	}

	for i, c := range cases {
		hash, err := HashPassword(c.pass)
		if err != nil {
			t.Errorf("Test case %v failed. error: %v", i, err)
		}
		match, err := CheckPasswordHash(c.pass, hash)
		if err != nil {
			t.Errorf("Test case %v failed. error: %v", i, err)
		}
		if !match {
			t.Errorf("test case %v failed. Password didn't match", i)
		}
	}
}
