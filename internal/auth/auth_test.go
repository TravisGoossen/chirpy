package auth

import (
	"net/http"
	"strings"
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
		expectedFail bool
	}{
		{
			userID:       uuid.New(),
			tokenSecret:  "secret",
			expectedFail: false,
		},
		{
			userID:       uuid.New(),
			tokenSecret:  "lieb!love!amore!haaaaarrrrrrrr",
			expectedFail: false,
		},
		{
			userID:       uuid.New(),
			tokenSecret:  "LETSFAILTHISTESTWOOOHOOOO",
			expectedFail: true,
		},
		{
			userID:       uuid.New(),
			tokenSecret:  "IsthisTaking too longgg?",
			expectedFail: true,
		},
	}

	for i, c := range cases {
		token, err := MakeJWT(c.userID, c.tokenSecret)
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
		token, err := MakeJWT(c.userID, c.tokenSecret)
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

func TestGetBearerToken(t *testing.T) {
	header1 := http.Header{
		"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	}
	header2 := http.Header{}
	header2.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	cases := []struct {
		headers       http.Header
		strippedToken string
	}{
		{
			headers: header1,
		},
		{
			headers: header2,
		},
	}

	for i, c := range cases {
		token, err := GetBearerToken(c.headers)
		if err != nil {
			t.Errorf("TestGearBearerToken failed on case #%v. error: %v", i, err)
		}
		strippedToken, _ := strings.CutPrefix(c.headers.Get("Authorization"), "Bearer ")
		if token != strippedToken {
			t.Errorf("TestGearBearerToken failed on case #%v. Token was not the expected token", i)
		}
	}
}

func TestMakeRefreshToken(t *testing.T) {
	token, err := MakeRefreshToken()
	if err != nil {
		t.FailNow()
	}
	if len(token) != 64 {
		t.FailNow()
	}
}
