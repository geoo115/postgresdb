package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
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
	ID                 int       `json:"id"`
	Title              string    `json:"title"`
	Content            string    `json:"content"`
	Username           string    `json:"username"`
	ReferrerUserID     int       `json:"referrer_user_id"`
	CompanyID          int       `json:"company_id"`
	RefereeClient      string    `json:"referee_client"`
	RefereeClientEmail string    `json:"referee_client_email"`
	CreatedAt          time.Time `json:"created_at"`
	Status             string    `json:"status"`
	CompanyName        string    `json:"company_name"`
}

func main() {
	user := "postgres"
	password := "mimi123"
	dbName := "databasetest3"

	createDatabaseIfNotExists(dbName, user, password)
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", user, password, dbName)
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
	}

	createTables()
	log.Println("Tables created successfully")

	// Initialize mux router
	r := mux.NewRouter()

	// Registering handlers
	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")
	r.HandleFunc("/create-referral", CreateReferralRequestHandler).Methods("POST")
	r.HandleFunc("/companies", GetCompaniesHandler).Methods("GET")
	r.HandleFunc("/referrals-sent", GetReferralsSentHandler).Methods("GET")
	r.HandleFunc("/referrals-received", GetReferralsReceivedHandler).Methods("GET")
	r.HandleFunc("/referral-request-action/approve/{referralRequestID}", ApproveReferralRequestHandler).Methods("POST")
	r.HandleFunc("/referral-request-action/deny/{referralRequestID}", DenyReferralRequestHandler).Methods("POST")
	r.HandleFunc("/users", GetAllUsersHandler).Methods("GET")
	r.HandleFunc("/users/{companyID}", GetUsersByCompanyHandler).Methods("GET")
	r.HandleFunc("/create-user", CreateUserHandler).Methods("POST")
	r.HandleFunc("/delete-user", DeleteUserHandler).Methods("POST")
	r.HandleFunc("/create-company", CreateCompanyHandler).Methods("POST")
	r.HandleFunc("/delete-company", DeleteCompanyHandler).Methods("POST")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// Function to create a database if it doesn't exist
func createDatabaseIfNotExists(dbName string, user string, password string) {
	connStr := fmt.Sprintf("user=%s password=%s dbname=postgres sslmode=disable", user, password)
	tempDB, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the PostgreSQL instance: %v", err)
	}
	defer tempDB.Close()

	// Check if the database exists
	var exists bool
	err = tempDB.QueryRow("SELECT EXISTS(SELECT datname FROM pg_catalog.pg_database WHERE datname = $1)", dbName).Scan(&exists)
	if err != nil {
		log.Fatalf("Failed to check if database exists: %v", err)
	}

	if !exists {
		// Create the database
		_, err = tempDB.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName))
		if err != nil {
			log.Fatalf("Failed to create database: %v", err)
		}
		log.Printf("Database %s created successfully", dbName)
	} else {
		log.Printf("Database %s already exists", dbName)
	}
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS companies (
			id SERIAL PRIMARY KEY,
			name TEXT UNIQUE NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			role TEXT NOT NULL,
			company_id INTEGER,
			FOREIGN KEY (company_id) REFERENCES companies(id)
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id SERIAL PRIMARY KEY,
			session_id TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);`,
		`CREATE TABLE IF NOT EXISTS referral_requests (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			referrer_user_id INTEGER NOT NULL,
			company_id INTEGER,
			referee_client TEXT NOT NULL,
			referee_client_email TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			status TEXT NOT NULL DEFAULT 'pending',
			FOREIGN KEY (referrer_user_id) REFERENCES users(id),
			FOREIGN KEY (company_id) REFERENCES companies(id)
		);`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatalf("Error executing query:\n%s\nError: %v", query, err)
		}
	}
}

func createSession(userID int) (string, error) {
	sessionID := generateSessionID()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err := db.Exec("INSERT INTO sessions (session_id, user_id, expires_at) VALUES ($1, $2, $3)", sessionID, userID, expiresAt)
	if err != nil {
		return "", err
	}
	return sessionID, nil
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	// Decode JSON request body into User struct
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if user.Email == "" || user.Username == "" || user.Password == "" || user.CompanyName == "" || user.Role == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Validate email format
	if !isValidEmail(user.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Check if company exists or create a new one
	var companyID int
	err = db.QueryRow("SELECT id FROM companies WHERE name = $1", user.CompanyName).Scan(&companyID)
	switch {
	case err == sql.ErrNoRows:
		// Company does not exist, insert it
		log.Printf("Company %s does not exist. Creating new company.", user.CompanyName)
		err = db.QueryRow("INSERT INTO companies (name) VALUES ($1) RETURNING id", user.CompanyName).Scan(&companyID)
		if err != nil {
			log.Printf("Error inserting company: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		log.Printf("New company created with ID: %d", companyID)
	case err != nil:
		// Some other error occurred
		log.Printf("Error checking company existence: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	default:
		log.Printf("Existing company found with ID: %d", companyID)
	}

	// Insert the user with hashed password and company ID
	log.Printf("Inserting user %s into company with ID %d", user.Username, companyID)
	_, err = db.Exec("INSERT INTO users (email, username, password, role, company_id) VALUES ($1, $2, $3, $4, $5)",
		user.Email, user.Username, hashedPassword, user.Role, companyID)
	if err != nil {
		log.Printf("Error inserting user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User registered successfully")
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

	// Validate email format
	if !isValidEmail(credentials.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, email, username, password, role, company_id FROM users WHERE email = $1", credentials.Email).
		Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Role, &user.CompanyID)
	if err != nil {
		log.Println("Error querying user:", err)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		log.Println("Error comparing password:", err)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	sessionID, err := createSession(user.ID)
	if err != nil {
		log.Println("Error creating session:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, // Secure session cookies
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No session found", http.StatusUnauthorized)
		return
	}
	_, err = db.Exec("DELETE FROM sessions WHERE session_id = $1", cookie.Value)
	if err != nil {
		log.Println("Error deleting session:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true, // Secure session cookies
	})
	w.WriteHeader(http.StatusOK)
}

func GetCompaniesHandler(w http.ResponseWriter, r *http.Request) {
	var userCount int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		log.Println("Error counting users:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If no users exist, allow public access to companies
	if userCount == 0 {
		fetchCompanies(w)
		return
	}

	// Proceed with session authentication if users exist
	sessionID, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user User
	err = db.QueryRow("SELECT u.id, u.email, u.username, u.password, u.role, u.company_id FROM users u "+
		"INNER JOIN sessions s ON u.id = s.user_id "+
		"WHERE s.session_id = $1", sessionID.Value).
		Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Role, &user.CompanyID)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fetchCompanies(w)
}

func fetchCompanies(w http.ResponseWriter) {
	var companies []Company
	rows, err := db.Query("SELECT id, name FROM companies")
	if err != nil {
		log.Println("Error fetching companies:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var company Company
		err := rows.Scan(&company.ID, &company.Name)
		if err != nil {
			log.Println("Error scanning company row:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		companies = append(companies, company)
	}

	if err := rows.Err(); err != nil {
		log.Println("Error iterating over company rows:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(companies) == 0 {
		companies = []Company{} // Ensure an empty slice is returned if no records found
	}
	json.NewEncoder(w).Encode(companies)
}

func CreateReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var user User
	err = db.QueryRow("SELECT u.id, u.email, u.username, u.password, u.role, u.company_id, c.name FROM users u "+
		"LEFT JOIN companies c ON u.company_id = c.id "+
		"INNER JOIN sessions s ON u.id = s.user_id "+
		"WHERE s.session_id = $1", sessionID.Value).
		Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.Role, &user.CompanyID, &user.CompanyName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var referralRequest ReferralRequest
	if err := json.NewDecoder(r.Body).Decode(&referralRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	referralRequest.Username = user.Username
	referralRequest.ReferrerUserID = user.ID
	referralRequest.CompanyID = user.CompanyID
	referralRequest.CompanyName = user.CompanyName

	// Validate referral request fields
	if referralRequest.Title == "" || referralRequest.Content == "" || referralRequest.RefereeClient == "" || !isValidEmail(referralRequest.RefereeClientEmail) {
		http.Error(w, "Invalid input fields", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO referral_requests (username, title, content, referrer_user_id, company_id, referee_client, referee_client_email) "+
		"VALUES ($1, $2, $3, $4, $5, $6, $7)",
		referralRequest.Username, referralRequest.Title, referralRequest.Content, referralRequest.ReferrerUserID,
		referralRequest.CompanyID, referralRequest.RefereeClient, referralRequest.RefereeClientEmail)
	if err != nil {
		log.Println("Error creating referral request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Helper function to validate email format
func isValidEmail(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domainParts := strings.Split(parts[1], ".")
	if len(domainParts) < 2 {
		return false
	}
	return true
}

func handleError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
	log.Println(msg)
}

func ApproveReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	_, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	referralRequestID, err := strconv.Atoi(vars["referralRequestID"])
	if err != nil {
		handleError(w, "Invalid referral request ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE referral_requests SET status = $1 WHERE id = $2", "Approved", referralRequestID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error approving referral request:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func DenyReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	_, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	referralRequestID, err := strconv.Atoi(vars["referralRequestID"])
	if err != nil {
		handleError(w, "Invalid referral request ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE referral_requests SET status = $1 WHERE id = $2", "Denied", referralRequestID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error denying referral request:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func GetReferralsSentHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var referralRequests []ReferralRequest
	rows, err := db.Query("SELECT r.id, r.title, r.content, r.username, r.referrer_user_id, r.company_id, r.referee_client, r.referee_client_email, r.created_at, r.status, c.name AS company_name "+
		"FROM referral_requests r "+
		"LEFT JOIN companies c ON r.company_id = c.id "+
		"WHERE r.referrer_user_id = $1 "+
		"ORDER BY r.created_at DESC", user.ID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error fetching referral requests:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var referralRequest ReferralRequest
		err := rows.Scan(&referralRequest.ID, &referralRequest.Title, &referralRequest.Content, &referralRequest.Username,
			&referralRequest.ReferrerUserID, &referralRequest.CompanyID, &referralRequest.RefereeClient, &referralRequest.RefereeClientEmail,
			&referralRequest.CreatedAt, &referralRequest.Status, &referralRequest.CompanyName)
		if err != nil {
			handleError(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error scanning referral request row:", err)
			return
		}
		referralRequests = append(referralRequests, referralRequest)
	}

	if err := rows.Err(); err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error iterating over referral request rows:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(referralRequests) == 0 {
		referralRequests = []ReferralRequest{}
	}
	json.NewEncoder(w).Encode(referralRequests)
}

func GetReferralsReceivedHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var referralRequests []ReferralRequest
	rows, err := db.Query("SELECT r.id, r.title, r.content, r.username, r.referrer_user_id, r.company_id, r.referee_client, r.referee_client_email, r.created_at, r.status, c.name AS company_name "+
		"FROM referral_requests r "+
		"LEFT JOIN companies c ON r.company_id = c.id "+
		"WHERE r.company_id = $1 "+
		"ORDER BY r.created_at DESC", user.CompanyID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error fetching referral requests:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var referralRequest ReferralRequest
		err := rows.Scan(&referralRequest.ID, &referralRequest.Title, &referralRequest.Content, &referralRequest.Username,
			&referralRequest.ReferrerUserID, &referralRequest.CompanyID, &referralRequest.RefereeClient, &referralRequest.RefereeClientEmail,
			&referralRequest.CreatedAt, &referralRequest.Status, &referralRequest.CompanyName)
		if err != nil {
			handleError(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error scanning referral request row:", err)
			return
		}
		referralRequests = append(referralRequests, referralRequest)
	}

	if err := rows.Err(); err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error iterating over referral request rows:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(referralRequests) == 0 {
		referralRequests = []ReferralRequest{}
	}
	json.NewEncoder(w).Encode(referralRequests)
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var existingUserID int
	err := db.QueryRow("SELECT id FROM users WHERE email = $1 OR username = $2", user.Email, user.Username).Scan(&existingUserID)
	if err != nil && err != sql.ErrNoRows {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error checking existing user:", err)
		return
	}
	if existingUserID > 0 {
		handleError(w, "User with given email or username already exists", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error hashing password:", err)
		return
	}
	user.Password = string(hashedPassword)

	err = db.QueryRow("INSERT INTO users (email, username, password, role, company_id) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		user.Email, user.Username, user.Password, user.Role, user.CompanyID).Scan(&user.ID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error creating user:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	sessionUser, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionUser.ID != user.ID && sessionUser.Role != "admin" {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if user.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			handleError(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error hashing password:", err)
			return
		}
		user.Password = string(hashedPassword)
	}

	query := "UPDATE users SET email = $1, username = $2, password = $3, role = $4, company_id = $5 WHERE id = $6"
	_, err = db.Exec(query, user.Email, user.Username, user.Password, user.Role, user.CompanyID, user.ID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error updating user:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	sessionUser, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionUser.ID != user.ID && sessionUser.Role != "admin" {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec("DELETE FROM users WHERE id = $1", user.ID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error deleting user:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	_, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var users []User
	rows, err := db.Query("SELECT u.id, u.email, u.username, u.role, u.company_id, c.name FROM users u " +
		"LEFT JOIN companies c ON u.company_id = c.id")
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error fetching users:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.Role, &user.CompanyID, &user.CompanyName)
		if err != nil {
			handleError(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error scanning user row:", err)
			return
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error iterating over user rows:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(users) == 0 {
		users = []User{}
	}
	json.NewEncoder(w).Encode(users)
}

func GetUsersByCompanyHandler(w http.ResponseWriter, r *http.Request) {
	_, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	companyID, err := strconv.Atoi(vars["companyID"])
	if err != nil {
		handleError(w, "Invalid company ID", http.StatusBadRequest)
		return
	}

	var users []User
	rows, err := db.Query("SELECT u.id, u.email, u.username, u.role, u.company_id, c.name FROM users u "+
		"LEFT JOIN companies c ON u.company_id = c.id WHERE u.company_id = $1", companyID)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error fetching users by company:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.Role, &user.CompanyID, &user.CompanyName)
		if err != nil {
			handleError(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error scanning user row:", err)
			return
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error iterating over user rows:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(users) == 0 {
		users = []User{}
	}
	json.NewEncoder(w).Encode(users)
}

func CreateCompanyHandler(w http.ResponseWriter, r *http.Request) {
	_, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var company Company
	if err := json.NewDecoder(r.Body).Decode(&company); err != nil {
		handleError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var existingCompanyID int
	err = db.QueryRow("SELECT id FROM companies WHERE name = $1", company.Name).Scan(&existingCompanyID)
	if err != nil && err != sql.ErrNoRows {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error checking existing company:", err)
		return
	}
	if existingCompanyID > 0 {
		handleError(w, "Company with given name already exists", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO companies (name) VALUES ($1)", company.Name)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error creating company:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(company)
}

func DeleteCompanyHandler(w http.ResponseWriter, r *http.Request) {
	_, err := getSessionUser(r)
	if err != nil {
		handleError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var company Company
	if err := json.NewDecoder(r.Body).Decode(&company); err != nil {
		handleError(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM companies WHERE name = $1", company.Name)
	if err != nil {
		handleError(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error deleting company:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func getSessionUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, fmt.Errorf("no session found")
	}

	var user User
	err = db.QueryRow("SELECT u.id, u.email, u.username, u.password, u.role, u.company_id, c.name AS company_name "+
		"FROM sessions s "+
		"INNER JOIN users u ON u.id = s.user_id "+
		"LEFT JOIN companies c ON u.company_id = c.id "+
		"WHERE s.session_id = $1 AND s.expires_at > $2", cookie.Value, time.Now()).Scan(
		&user.ID, &user.Email, &user.Username, &user.Password, &user.Role, &user.CompanyID, &user.CompanyName)

	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("session not found or expired")
	case err != nil:
		return nil, fmt.Errorf("error retrieving session from database: %v", err)
	}

	return &user, nil
}
