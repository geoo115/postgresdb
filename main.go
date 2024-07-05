package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	Role        string `json:"role"`
	CompanyID   int    `json:"company_id"`
	CompanyName string `json:"company_name"`
}

type Company struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type ReferralRequest struct {
	ID                 int    `json:"id"`
	Title              string `json:"title"`
	Content            string `json:"content"`
	ReferrerUserID     int    `json:"referrer_user_id"`
	CompanyID          int    `json:"company_id"`
	RefereeClient      string `json:"referee_client"`
	RefereeClientEmail string `json:"referee_client_email"`
	CreatedAt          string `json:"created_at"`
	Status             string `json:"status"`
	Username           string `json:"username"`
}

type PageData struct {
	UserID               int                       `json:"user_id"`
	Username             string                    `json:"username"`
	IsAuthenticated      bool                      `json:"is_authenticated"`
	Role                 string                    `json:"role"`
	CompanyID            int                       `json:"company_id"`
	Companies            []Company                 `json:"companies"`
	AllUsers             []User                    `json:"all_users"`
	CompanyName          string                    `json:"company_name"`
	CompanyUsers         []User                    `json:"company_users"`
	UserActivities       []Activity                `json:"user_activities"`
	ReferralRequests     []ReferralRequest         `json:"referral_requests"`
	UserReferralRequests map[int][]ReferralRequest `json:"user_referral_requests"`
}

type Activity struct {
	CreatedAt time.Time `json:"created_at"`
}

// func createTables() {
// 	queries := []string{
// 		`CREATE TABLE IF NOT EXISTS companies (
// 			id SERIAL PRIMARY KEY,
// 			name TEXT UNIQUE NOT NULL
// 		);`,
// 		`CREATE TABLE IF NOT EXISTS users (
// 			id SERIAL PRIMARY KEY,
// 			email TEXT UNIQUE NOT NULL,
// 			username TEXT NOT NULL,
// 			password TEXT NOT NULL,
// 			role TEXT NOT NULL,
// 			company_id INTEGER,
// 			FOREIGN KEY (company_id) REFERENCES companies(id)
// 		);`,
// 		`CREATE TABLE IF NOT EXISTS roles (
// 			id SERIAL PRIMARY KEY,
// 			name TEXT UNIQUE NOT NULL
// 		);`,
// 		`CREATE TABLE IF NOT EXISTS user_roles (
// 			user_id INTEGER NOT NULL,
// 			role_id INTEGER NOT NULL,
// 			FOREIGN KEY (user_id) REFERENCES users(id),
// 			FOREIGN KEY (role_id) REFERENCES roles(id)
// 		);`,
// 		`CREATE TABLE IF NOT EXISTS sessions (
// 			id SERIAL PRIMARY KEY,
// 			session_id TEXT UNIQUE NOT NULL,
// 			user_id INTEGER NOT NULL,
// 			expires_at TIMESTAMP NOT NULL,
// 			FOREIGN KEY (user_id) REFERENCES users(id)
// 		);`,
// 		`CREATE TABLE IF NOT EXISTS referral_requests (
// 			id SERIAL PRIMARY KEY,
// 			title TEXT NOT NULL,
// 			content TEXT NOT NULL,
// 			referrer_user_id INTEGER NOT NULL,
// 			company_id INTEGER,
// 			referee_client TEXT NOT NULL,
// 			referee_client_email TEXT NOT NULL,
// 			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
// 			status TEXT NOT NULL DEFAULT 'pending',
// 			FOREIGN KEY (referrer_user_id) REFERENCES users(id),
// 			FOREIGN KEY (company_id) REFERENCES companies(id)
// 		);`,
// 	}

// 	for _, query := range queries {
// 		_, err := db.Exec(query)
// 		if err != nil {
// 			log.Fatalf("Error executing query '%s': %v", query, err)
// 		}
// 	}
// }

func init() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Database connection setup
	connStr := "postgres://postgres:mimi123@localhost:5432/database1?sslmode=disable"

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging the database: %v", err)
	}

	// Ensure tables are created
	// createTables()
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/create-referral", CreateReferralRequestHandler).Methods("POST")
	r.HandleFunc("/referral-request", ReferralRequestHandler).Methods("GET")
	r.HandleFunc("/submit-referral-request", SubmitReferralRequestHandler).Methods("POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")
	r.HandleFunc("/referral-request-action", HandleReferralRequestAction).Methods("POST")
	r.HandleFunc("/user-profile", UserProfileHandler).Methods("GET")
	r.HandleFunc("/admin-profile", AdminProfileHandler).Methods("GET")
	r.HandleFunc("/platform-admin", PlatformAdminHandler).Methods("GET")
	r.HandleFunc("/super-admin", SuperAdminHandler).Methods("GET")
	r.HandleFunc("/create-company", CreateCompanyHandler).Methods("POST")
	r.HandleFunc("/delete-company", DeleteCompanyHandler).Methods("POST")
	r.HandleFunc("/create-user", CreateUserHandler).Methods("POST")
	r.HandleFunc("/update-user", UpdateUserHandler).Methods("POST")
	r.HandleFunc("/delete-user", DeleteUserHandler).Methods("POST")

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(headers, methods, origins)(r)))
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var companyID int
	err = db.QueryRow("SELECT id FROM companies WHERE name = $1", user.CompanyName).Scan(&companyID)
	if err == sql.ErrNoRows {
		err = db.QueryRow("INSERT INTO companies (name) VALUES ($1) RETURNING id", user.CompanyName).Scan(&companyID)
		if err != nil {
			log.Println("Error inserting company:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		log.Println("Error querying company:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO users (email, username, password, role, company_id) VALUES ($1, $2, $3, $4, $5)", user.Email, user.Username, hashedPassword, user.Role, companyID)
	if err != nil {
		log.Println("Error inserting user:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var storedPassword string
	var userID, companyID int
	var role string
	err := db.QueryRow("SELECT id, password, role, company_id FROM users WHERE email = $1", credentials.Email).Scan(&userID, &storedPassword, &role, &companyID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		} else {
			log.Println("Error querying user:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	sessionID := CreateSession(userID)
	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	})
	json.NewEncoder(w).Encode(map[string]string{"role": role})
}

func CreateReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var referralRequest ReferralRequest
	if err := json.NewDecoder(r.Body).Decode(&referralRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec(
		"INSERT INTO referral_requests (title, content, referrer_user_id, company_id, referee_client, referee_client_email) VALUES ($1, $2, $3, $4, $5, $6)",
		referralRequest.Title, referralRequest.Content, pageData.UserID, pageData.CompanyID, referralRequest.RefereeClient, referralRequest.RefereeClientEmail,
	)
	if err != nil {
		log.Println("Error inserting referral request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func ReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	companies, err := GetAllCompanies()
	if err != nil {
		log.Println("Error fetching companies:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(companies)
}

func SubmitReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var referralRequest ReferralRequest
	if err := json.NewDecoder(r.Body).Decode(&referralRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("UPDATE referral_requests SET status = $1 WHERE id = $2", referralRequest.Status, referralRequest.ID)
	if err != nil {
		log.Println("Error updating referral request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusOK)
}

func HandleReferralRequestAction(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var referralRequest ReferralRequest
	if err := json.NewDecoder(r.Body).Decode(&referralRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("UPDATE referral_requests SET status = $1 WHERE id = $2", referralRequest.Status, referralRequest.ID)
	if err != nil {
		log.Println("Error updating referral request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func UserProfileHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	users, err := getUsersByCompany(pageData.CompanyID)
	if err != nil {
		log.Println("Error fetching users:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func AdminProfileHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	users, err := getUsersByCompany(pageData.CompanyID)
	if err != nil {
		log.Println("Error fetching users:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(users)
}

func PlatformAdminHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	companies, err := GetAllCompanies()
	if err != nil {
		log.Println("Error fetching companies:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(companies)
}

func SuperAdminHandler(w http.ResponseWriter, r *http.Request) {
	pageData := GetAuthenticatedUserData(r)
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	companies, err := GetAllCompanies()
	if err != nil {
		log.Println("Error fetching companies:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(companies)
}

func getUsersByCompany(companyID int) ([]User, error) {
	rows, err := db.Query("SELECT id, email, username, role, company_id FROM users WHERE company_id = $1", companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.Role, &user.CompanyID)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// func getReferralRequestsByUserID(userID int) ([]ReferralRequest, error) {
// 	rows, err := db.Query("SELECT id, title, content, referrer_user_id, company_id, referee_client, referee_client_email, created_at, status FROM referral_requests WHERE referrer_user_id = $1", userID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer rows.Close()
// 	var requests []ReferralRequest
// 	for rows.Next() {
// 		var request ReferralRequest
// 		err := rows.Scan(&request.ID, &request.Title, &request.Content, &request.ReferrerUserID, &request.CompanyID, &request.RefereeClient, &request.RefereeClientEmail, &request.CreatedAt, &request.Status)
// 		if err != nil {
// 			return nil, err
// 		}
// 		requests = append(requests, request)
// 	}
// 	return requests, nil
// }

func GetCompanyNameByID(companyID int) (string, error) {
	var companyName string
	err := db.QueryRow("SELECT name FROM companies WHERE id = $1", companyID).Scan(&companyName)
	if err != nil {
		return "", err
	}
	return companyName, nil
}

func GetAllCompanies() ([]Company, error) {
	rows, err := db.Query("SELECT id, name FROM companies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var companies []Company
	for rows.Next() {
		var company Company
		err := rows.Scan(&company.ID, &company.Name)
		if err != nil {
			return nil, err
		}
		companies = append(companies, company)
	}
	return companies, nil
}

func CreateCompanyHandler(w http.ResponseWriter, r *http.Request) {
	var company Company
	if err := json.NewDecoder(r.Body).Decode(&company); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("INSERT INTO companies (name) VALUES ($1)", company.Name)
	if err != nil {
		log.Println("Error inserting company:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func DeleteCompanyHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CompanyID int `json:"company_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM companies WHERE id = $1", request.CompanyID)
	if err != nil {
		log.Println("Error deleting company:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO users (email, username, password, role, company_id) VALUES ($1, $2, $3, $4, $5)", user.Email, user.Username, hashedPassword, user.Role, user.CompanyID)
	if err != nil {
		log.Println("Error inserting user:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("UPDATE users SET email = $1, username = $2, role = $3, company_id = $4 WHERE id = $5", user.Email, user.Username, user.Role, user.CompanyID, user.ID)
	if err != nil {
		log.Println("Error updating user:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		UserID int `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("DELETE FROM users WHERE id = $1", request.UserID)
	if err != nil {
		log.Println("Error deleting user:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file:", err)
	}
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Error opening database connection:", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
}

func CreateSession(userID int) string {
	sessionID := GenerateSessionID()
	_, err := db.Exec("INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)", sessionID, userID, time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		log.Fatal("Error creating session:", err)
	}
	return sessionID
}

func GenerateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("Error generating session ID:", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func GetAuthenticatedUserData(r *http.Request) PageData {
	var pageData PageData
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		pageData.IsAuthenticated = false
		return pageData
	}
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = $1 AND expires_at > NOW()", sessionCookie.Value).Scan(&userID)
	if err != nil {
		pageData.IsAuthenticated = false
		return pageData
	}
	var username, role string
	var companyID int
	err = db.QueryRow("SELECT username, role, company_id FROM users WHERE id = $1", userID).Scan(&username, &role, &companyID)
	if err != nil {
		pageData.IsAuthenticated = false
		return pageData
	}
	pageData.UserID = userID
	pageData.Username = username
	pageData.Role = role
	pageData.CompanyID = companyID
	pageData.IsAuthenticated = true
	return pageData
}
