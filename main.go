package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

func main() {
	godotenv.Load()
	JWTSecret := os.Getenv("JWT_SECRET")
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Failed to connect to DB. err: %v", err)
	}

	apiCfg := ApiConfig{
		dbQueries: database.New(db),
		platform:  os.Getenv("PLATFORM"),
		JWTSecret: JWTSecret,
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
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/chirps", apiCfg.createNewChirpEndpoint)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.GetSpecificChirp)
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

func (cfg *ApiConfig) createNewUserEndpoint(w http.ResponseWriter, r *http.Request) {
	type User struct {
		ID        uuid.UUID `json:"id,omitempty"`
		CreatedAt time.Time `json:"created_at,omitempty"`
		UpdatedAt time.Time `json:"updated_at,omitempty"`
		Email     string    `json:"email"`
		Password  string    `json:"password,omitempty"`
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
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}

	writeJSONResponse(w, http.StatusCreated, user)
}

func (cfg *ApiConfig) login(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Email              string `json:"email"`
		Password           string `json:"password"`
		Expires_in_seconds int    `json:"expires_in_seconds,omitempty"`
	}
	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
	}
	req := requestBody{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to login. error: %v", err), http.StatusInternalServerError)
		return
	}
	if req.Expires_in_seconds == 0 || req.Expires_in_seconds > 3600 {
		req.Expires_in_seconds = 3600
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
	token, err := auth.MakeJWT(dbUser.ID, cfg.JWTSecret, time.Duration(req.Expires_in_seconds)*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create jwt token. error: %v", err), http.StatusInternalServerError)
		return
	}

	responseUser := responseBody{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
		Token:     token,
	}
	writeJSONResponse(w, http.StatusOK, responseUser)
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
			Body: chirp,
			UserID: uuid.NullUUID{
				UUID:  JWTUUID,
				Valid: true,
			},
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
			User_id:    chirpStruct.UserID.UUID.String(),
		},
	)
}

func (cfg *ApiConfig) GetSpecificChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDString := r.PathValue("chirpID")
	chirpIDUUID, err := uuid.Parse(chirpIDString)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get specific chirp. error: %v", err), http.StatusInternalServerError)
		return
	}
	chirp, err := cfg.dbQueries.GetSpecificChirp(r.Context(), chirpIDUUID)
	if err != nil {
		http.Error(w, fmt.Sprintf("chirp does not exist. error: %v", err), http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, convertChirpStruct(chirp))
}

func (cfg *ApiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to retrieve all chirps. error: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, convertChirpSlice(chirps))

}

func convertChirpStruct(chirp database.Chirp) chirpResponse {
	return chirpResponse{
		Id:         chirp.ID.String(),
		Created_at: chirp.CreatedAt.String(),
		Updated_at: chirp.UpdatedAt.String(),
		Body:       chirp.Body,
		User_id:    chirp.UserID.UUID.String(),
	}
}

func convertChirpSlice(chirps []database.Chirp) []chirpResponse {
	newSlice := make([]chirpResponse, len(chirps))
	for i, v := range chirps {
		newSlice[i] = convertChirpStruct(v)
	}
	return newSlice
}
