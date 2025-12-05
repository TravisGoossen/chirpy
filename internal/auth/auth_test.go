package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestJWTValidAndExpired(t *testing.T) {
	cases := []struct {
		userID       uuid.UUID
		tokenSecret  string
		expiresIn    time.Duration
		expectedFail bool
	}{
		{
			userID:       uuid.New(),
			tokenSecret:  "secret",
			expiresIn:    time.Duration(time.Second * 3),
			expectedFail: false,
		},
		{
			userID:       uuid.New(),
			tokenSecret:  "lieb!love!amore!haaaaarrrrrrrr",
			expiresIn:    time.Duration(time.Second * 1),
			expectedFail: false,
		},
		{
			userID:       uuid.New(),
			tokenSecret:  "LETSFAILTHISTESTWOOOHOOOO",
			expiresIn:    time.Duration(time.Millisecond * 500),
			expectedFail: true,
		},
		{
			userID:       uuid.New(),
			tokenSecret:  "IsthisTaking too longgg?",
			expiresIn:    time.Duration(time.Second * 2),
			expectedFail: true,
		},
	}

	for i, c := range cases {
		token, err := MakeJWT(c.userID, c.tokenSecret, c.expiresIn)
		if err != nil {
			t.Errorf("Failed in TestJWT(MakeJWT) case #%v. error: %v\n", i, err)
		}
		if i == 2 {
			time.Sleep(time.Second * 1)
		}
		if i == 3 {
			time.Sleep(time.Second * 3)
		}
		uuid, err := ValidateJWT(token, c.tokenSecret)

		switch c.expectedFail {
		case false:
			if err != nil {
				t.Errorf("Failed in TestJWT(ValidateJWT) case #%v. error: %v\n", i, err)
			}
			if uuid != c.userID {
				t.Errorf("Failed in TestJWT(uuid check) case #%v. UUID does not match userID\n", i)
			}
		case true:
			if err == nil {
				t.Errorf("Failed in TestJWT(ValidateJWT) case #%v. Test expected to fail, but did not.", i)
			}
			if uuid == c.userID {
				t.Errorf("Failed in TestJWT(uuid check) case #%v. Test expected to fail, but did not.", i)
			}
		}

	}
}

func TestJWTWrongSecret(t *testing.T) {
	cases := []struct {
		userID      uuid.UUID
		tokenSecret string
		wrongSecret string
		expiresIn   time.Duration
	}{
		{
			userID:      uuid.New(),
			tokenSecret: "ShhhhthisisaSECRET",
			wrongSecret: "shhTH!$!S4S3creT",
			expiresIn:   time.Duration(time.Second * 1),
		},
		{
			userID:      uuid.New(),
			tokenSecret: "IloveMUSIC",
			wrongSecret: "iHATEmusic",
			expiresIn:   time.Duration(time.Second * 1),
		},
		{
			userID:      uuid.New(),
			tokenSecret: "theNewLordeAlbumIsAmazing",
			wrongSecret: "soIsTheNewLinkinParkAlbum",
			expiresIn:   time.Duration(time.Second * 1),
		},
	}

	for i, c := range cases {
		token, err := MakeJWT(c.userID, c.tokenSecret, c.expiresIn)
		if err != nil {
			t.Errorf("Failed in TestJWTWrongSecret(MakeJWT) case #%v. error: %v\n", i, err)
		}

		uuid, err := ValidateJWT(token, c.wrongSecret)
		if err == nil {
			t.Errorf("Failed in TestJWTWrongSecret(ValidateJWT) case #%v. error: %v\n", i, err)
		}
		if uuid == c.userID {
			t.Errorf("Failed in TestJWTWrongSecret(uuid check) case #%v. UUID does not match userID\n", i)
		}
	}
}
