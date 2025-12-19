package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TravisGoossen/chirpy/internal/auth"
	"github.com/TravisGoossen/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// This struct is identical to database.Chirp except that it has proper json tags needed to make the right http responses
type chirpResponse struct {
	Id         string `json:"id"`
	Created_at string `json:"created_at"`
	Updated_at string `json:"updated_at"`
	Body       string `json:"body"`
	User_id    string `json:"user_id"`
}

type ApiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	JWTSecret      string
	PolkaAPIKey    string
}

func main() {
	godotenv.Load()
	JWTSecret := os.Getenv("JWT_SECRET")
	PolkaAPIKey := os.Getenv("POLKA_KEY")
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Failed to connect to DB. err: %v", err)
	}

	apiCfg := ApiConfig{
		dbQueries:   database.New(db),
		platform:    os.Getenv("PLATFORM"),
		JWTSecret:   JWTSecret,
		PolkaAPIKey: PolkaAPIKey,
	}
	mux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", ReadinessEndpoint)
	mux.HandleFunc("GET /admin/metrics", apiCfg.displayMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetAllUsers)
	mux.HandleFunc("POST /api/users", apiCfg.createNewUserEndpoint)
	mux.HandleFunc("PUT /api/users", apiCfg.updateEmailPasswordEndpoint)
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshEndpoint)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshToken)
	mux.HandleFunc("POST /api/chirps", apiCfg.createNewChirpEndpoint)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getSpecificChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebHooks)
	server.ListenAndServe()
}

func writeJSONResponse(w http.ResponseWriter, statusCode int, payload any) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "error: Something went wrong", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(payloadJSON)
}

func checkProfanity(text string) (string, bool) {
	profanityFound := false
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(text, " ")
	for i, word := range words {
		if slices.Contains(badWords, strings.ToLower(word)) {
			words[i] = "****"
			profanityFound = true
		}
	}
	return strings.Join(words, " "), profanityFound
}

func ReadinessEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Returns the original OR newly cleaned chirp, and an error
func validateChirp(chirp string) (string, error) {

	if len(chirp) > 140 {
		return chirp, errors.New("chirp is too long")
	}

	if cleanedChirp, profanityFound := checkProfanity(chirp); profanityFound {
		return cleanedChirp, nil
	}

	return chirp, nil
}

func (cfg *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *ApiConfig) displayMetrics(w http.ResponseWriter, r *http.Request) {
	currentHits := cfg.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
	<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
	`, currentHits)))
}

func (cfg *ApiConfig) createNewUserEndpoint(w http.ResponseWriter, r *http.Request) {
	type User struct {
		ID          uuid.UUID `json:"id,omitempty"`
		CreatedAt   time.Time `json:"created_at,omitempty"`
		UpdatedAt   time.Time `json:"updated_at,omitempty"`
		Email       string    `json:"email"`
		Password    string    `json:"password,omitempty"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}
	req := User{}
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&req)

	if req.Password == "" {
		http.Error(w, "failed to create user. no password provided.", http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create user. error: %v", err), http.StatusInternalServerError)
		return
	}

	dbUser, err := cfg.dbQueries.CreateUser(
		r.Context(),
		database.CreateUserParams{
			Email:          req.Email,
			HashedPassword: hash,
		},
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create user. error: %v", err), http.StatusInternalServerError)
		return
	}

	user := User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
	}

	writeJSONResponse(w, http.StatusCreated, user)
}

func (cfg *ApiConfig) login(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type responseBody struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}
	req := requestBody{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to login. error: %v", err), http.StatusInternalServerError)
		return
	}

	dbUser, err := cfg.dbQueries.Login(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}
	match, err := auth.CheckPasswordHash(req.Password, dbUser.HashedPassword)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to login. error: %v", err), http.StatusInternalServerError)
		return
	}

	if !match {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}
	token, err := auth.MakeJWT(dbUser.ID, cfg.JWTSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create jwt token. error: %v", err), http.StatusInternalServerError)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create refresh token. error: %v", err), http.StatusInternalServerError)
	}
	cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: time.Now().Add(1440 * time.Hour),
	})

	responseUser := responseBody{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		IsChirpyRed:  dbUser.IsChirpyRed,
		Token:        token,
		RefreshToken: refreshToken,
	}
	writeJSONResponse(w, http.StatusOK, responseUser)
}

func (cfg *ApiConfig) updateEmailPasswordEndpoint(w http.ResponseWriter, r *http.Request) {
	type User struct {
		ID          uuid.UUID `json:"id,omitempty"`
		CreatedAt   time.Time `json:"created_at,omitempty"`
		UpdatedAt   time.Time `json:"updated_at,omitempty"`
		Email       string    `json:"email"`
		Password    string    `json:"password,omitempty"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}
	reqUser := User{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&reqUser)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decode request body. error: %v", err), http.StatusInternalServerError)
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to retrieve token. error: %v", err), http.StatusUnauthorized)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.JWTSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("jwt validation failed. error: %v", err), http.StatusUnauthorized)
		return
	}
	hashedPass, err := auth.HashPassword(reqUser.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to has password. error: %v", err), http.StatusBadGateway)
		return
	}
	cfg.dbQueries.UpdateEmailPassword(
		r.Context(),
		database.UpdateEmailPasswordParams{
			ID:             userID,
			Email:          reqUser.Email,
			HashedPassword: hashedPass,
		})
	dbUser, err := cfg.dbQueries.GetUserInfo(r.Context(), userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get user info. error: %v", err), http.StatusInternalServerError)
		return
	}
	responseUser := User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
	}
	writeJSONResponse(w, http.StatusOK, responseUser)
}

func (cfg *ApiConfig) refreshEndpoint(w http.ResponseWriter, r *http.Request) {
	type responseBody struct {
		Token string `json:"token"`
	}
	refToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get bearer token. error: %v", err), http.StatusBadRequest)
		return
	}
	userID, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get refresh token. error: %v", err), http.StatusUnauthorized)
		return
	}
	accToken, err := auth.MakeJWT(userID, cfg.JWTSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create jwt token. error: %v", err), http.StatusInternalServerError)
		return
	}
	response := responseBody{
		Token: accToken,
	}
	writeJSONResponse(w, http.StatusOK, response)
}

func (cfg *ApiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get bearer token. error: %v", err), http.StatusBadRequest)
		return
	}
	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to revoke refresh token. error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusNoContent, nil)
}

func (cfg *ApiConfig) resetAllUsers(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		http.Error(w, "This is only accessible in a developer environment", http.StatusForbidden)
		return
	}

	err := cfg.dbQueries.DeleteUsers(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete all users. error: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("All rows in 'users' table successfully deleted\n"))
}

func (cfg *ApiConfig) createNewChirpEndpoint(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Body    string `json:"body"`
		User_id string `json:"user_id"`
	}
	type responseBody struct {
		Id         string `json:"id"`
		Created_at string `json:"created_at"`
		Updated_at string `json:"updated_at"`
		Body       string `json:"body"`
		User_id    string `json:"user_id"`
	}
	req := requestBody{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create new chirp1. error: %v", err), http.StatusInternalServerError)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create new chirp2. error: %v", err), http.StatusInternalServerError)
		return
	}
	JWTUUID, err := auth.ValidateJWT(token, cfg.JWTSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create new chirp3. error: %v", err), http.StatusUnauthorized)
		return
	}

	chirp, err := validateChirp(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	chirpStruct, err := cfg.dbQueries.CreateChirp(
		r.Context(),
		database.CreateChirpParams{
			Body:   chirp,
			UserID: JWTUUID,
		},
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create new chirp. error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(
		w,
		http.StatusCreated,
		responseBody{
			Id:         chirpStruct.ID.String(),
			Created_at: chirpStruct.CreatedAt.String(),
			Updated_at: chirpStruct.UpdatedAt.String(),
			Body:       chirpStruct.Body,
			User_id:    chirpStruct.UserID.String(),
		},
	)
}

func (cfg *ApiConfig) getSpecificChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDString := r.PathValue("chirpID")
	chirpIDUUID, err := uuid.Parse(chirpIDString)
	if err != nil {
		log.Printf("failed to parse chirpID %v: %v", chirpIDString, err)
		http.Error(w, "invalid chirp ID", http.StatusBadRequest)
		return
	}
	chirp, err := cfg.dbQueries.GetSpecificChirp(r.Context(), chirpIDUUID)
	if err != nil {
		log.Printf("failed to find chirpID in DB :%v: %v", chirpIDString, err)
		http.Error(w, "chirp not found", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, convertChirpStruct(chirp))
}

func (cfg *ApiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	authorID := r.URL.Query().Get("author_id")
	if len(authorID) > 0 {
		authorIDUUID, err := uuid.Parse(authorID)
		if err != nil {
			log.Printf("failed to parse author as uuid: %v", err)
			http.Error(w, "invalid author id", http.StatusBadRequest)
			return
		}
		chirps, err := cfg.dbQueries.GetChirpsByAuthor(r.Context(), authorIDUUID)
		if err != nil {
			log.Printf("DB query GetChirpsByAuthor failed: %v", err)
			http.Error(w, "no chirps found from this author", http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusOK, convertChirpSlice(chirps))
		return
	}

	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		log.Printf("DB query GetChirps failed: %v", err)
		http.Error(w, "failed to retrieve chirps", http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, http.StatusOK, convertChirpSlice(chirps))

}

func (cfg *ApiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("failed to get bearer token on deleteChirp. error: %v", err)
		http.Error(w, "unathorized access", http.StatusUnauthorized)
		return
	}
	userUUID, err := auth.ValidateJWT(token, cfg.JWTSecret)
	if err != nil {
		log.Printf("failed to validate JWT %v. %v", userUUID.String(), err)
		http.Error(w, "unathorized access", http.StatusUnauthorized)
		return
	}

	ChirpIDString := r.PathValue("chirpID")
	ChirpIDUUID, err := uuid.Parse(ChirpIDString)
	if err != nil {
		log.Printf("failed to parse chirpID %v: %v", ChirpIDString, err)
		http.Error(w, "invalid chirp ID", http.StatusBadRequest)
		return
	}
	chirp, err := cfg.dbQueries.GetSpecificChirp(r.Context(), ChirpIDUUID)
	if err != nil {
		log.Printf("failed to find chirp %v: %v", ChirpIDString, err)
		http.Error(w, "chirp not found", http.StatusNotFound)
		return
	}

	if userUUID != chirp.UserID {
		http.Error(w, "unathorized access", http.StatusForbidden)
		return
	}

	err = cfg.dbQueries.DeleteChirp(r.Context(), ChirpIDUUID)
	if err != nil {
		log.Printf("failed to delete chirp %v: %v", ChirpIDString, err)
		http.Error(w, "failed to delete chirp", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusNoContent, nil)
}

func (cfg *ApiConfig) polkaWebHooks(w http.ResponseWriter, r *http.Request) {
	APIKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		log.Printf("failed to get api key from polkaWebHooks endpoint: %v", err)
		http.Error(w, "no API key provided", http.StatusUnauthorized)
		return
	}
	if APIKey != cfg.PolkaAPIKey {
		http.Error(w, "invalid API key", http.StatusUnauthorized)
		return
	}
	type requestBody struct {
		Event string `json:"event"`
		Data  struct {
			User_id string `json:"user_id"`
		} `json:"data"`
	}
	req := requestBody{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&req)
	if err != nil {
		log.Printf("failed to decode request body. %v", err)
		http.Error(w, "web hook failed", http.StatusInternalServerError)
		return
	}
	if req.Event != "user.upgraded" {
		http.Error(w, "unexpected event", http.StatusNoContent)
		return
	}
	userIDUUID, err := uuid.Parse(req.Data.User_id)
	if err != nil {
		log.Printf("failed to parse user ID from request: %v", err)
		http.Error(w, "bad user id", http.StatusBadRequest)
		return
	}
	_, err = cfg.dbQueries.UpgradeUserRed(r.Context(), userIDUUID)
	if err != nil {
		log.Printf("failed to upgrade user to red: %v", err)
		http.Error(w, "user id not found", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusNoContent, "")
}

func convertChirpStruct(chirp database.Chirp) chirpResponse {
	return chirpResponse{
		Id:         chirp.ID.String(),
		Created_at: chirp.CreatedAt.String(),
		Updated_at: chirp.UpdatedAt.String(),
		Body:       chirp.Body,
		User_id:    chirp.UserID.String(),
	}
}

func convertChirpSlice(chirps []database.Chirp) []chirpResponse {
	newSlice := make([]chirpResponse, len(chirps))
	for i, v := range chirps {
		newSlice[i] = convertChirpStruct(v)
	}
	return newSlice
}
