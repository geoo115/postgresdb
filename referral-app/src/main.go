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
		`CREATE TABLE IF NOT EXISTS roles (
			id SERIAL PRIMARY KEY,
			name TEXT UNIQUE NOT NULL
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

func main() {
	user := "postgres"
	password := "mimi123"
	dbName := "databasetest"

	// Create the database if it does not exist
	createDatabaseIfNotExists(dbName, user, password)

	// Connect to the newly created database
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", user, password, dbName)
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer db.Close()

	// Verify the connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
	}

	createTables()
	log.Println("Tables created successfully")

	r := mux.NewRouter()

	r.HandleFunc("/register", RegisterUserHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/create-referral", CreateReferralRequestHandler).Methods("POST")
	r.HandleFunc("/referral-request", ReferralRequestHandler).Methods("GET")
	r.HandleFunc("/submit-referral-request", SubmitReferralRequestHandler).Methods("POST")
	r.HandleFunc("/referral-requests/{companyID}", GetReferralRequestsByCompanyIDHandler).Methods("GET")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")
	r.HandleFunc("/referral-request-action", HandleReferralRequestAction).Methods("POST")
	r.HandleFunc("/user-profile", UserProfileHandler).Methods("GET")
	r.HandleFunc("/admin-profile", AdminProfileHandler).Methods("GET")
	r.HandleFunc("/platform-admin", PlatformAdminHandler).Methods("GET")
	r.HandleFunc("/super-admin", SuperAdminHandler).Methods("GET")
	r.HandleFunc("/create-company", CreateCompanyHandler).Methods("POST")
	r.HandleFunc("/delete-company", DeleteCompanyHandler).Methods("POST")
	r.HandleFunc("/create-user", CreateUserHandler).Methods("POST")
	r.HandleFunc("/update-user/{id}", UpdateUserHandler).Methods("POST")
	r.HandleFunc("/delete-user", DeleteUserHandler).Methods("POST")

	// CORS setup
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Start Server on port 8000
	handler := c.Handler(r)
	http.ListenAndServe(":8000", handler)
}

func RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var newUser User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	newUser.Password = string(hashedPassword)

	// Insert the new user into the database
	_, err = db.Exec("INSERT INTO users (email, username, password, role, company_id) VALUES ($1, $2, $3, $4, $5)",
		newUser.Email, newUser.Username, newUser.Password, newUser.Role, newUser.CompanyID)
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
		Name:    "session_id",
		Value:   sessionID,
		Expires: time.Now().Add(24 * time.Hour),
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
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

	// Ensure Username is populated correctly
	referralRequest.Username = pageData.Username

	// Log the referral request data
	log.Printf("Received referral request: %+v\n", referralRequest)

	// Insert new referral request into the database
	_, err := db.Exec(
		"INSERT INTO referral_requests (title, content, username, referrer_user_id, company_id, referee_client, referee_client_email) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		referralRequest.Title, referralRequest.Content, referralRequest.Username, pageData.UserID, pageData.CompanyID, referralRequest.RefereeClient, referralRequest.RefereeClientEmail,
	)
	if err != nil {
		log.Println("Error inserting referral request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func ReferralRequestHandler(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user data from the request
	pageData := GetAuthenticatedUserData(r)

	// Check if the user is authenticated
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch all referral requests from the database
	referralRequests, err := GetAllReferralRequests()
	if err != nil {
		log.Println("Error fetching referral requests:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If there's a company ID parameter in the request, filter by that company
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr != "" {
		companyID, err := strconv.Atoi(companyIDStr) // Convert string to int
		if err != nil {
			log.Println("Error converting company ID to integer:", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		referralRequestsByCompany, err := GetReferralRequestsByCompanyID(companyID)
		if err != nil {
			log.Println("Error fetching referral requests by company ID:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		// Merge referralRequestsByCompany with referralRequests
		referralRequests = append(referralRequests, referralRequestsByCompany...)
	}

	// Encode referral requests data as JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(referralRequests)
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
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
	})

	w.WriteHeader(http.StatusOK)
}

func UserProfileHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = $1 AND expires_at > NOW()", sessionCookie.Value).Scan(&userID)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user struct {
		Email     string `json:"email"`
		Username  string `json:"username"`
		Role      string `json:"role"`
		CompanyID int    `json:"company_id"`
	}

	err = db.QueryRow("SELECT email, username, role, company_id FROM users WHERE id = $1", userID).Scan(&user.Email, &user.Username, &user.Role, &user.CompanyID)
	if err != nil {
		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"email":    user.Email,
		"username": user.Username,
		"role":     user.Role,
		"company":  user.CompanyID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

	// Initialize the data structure
	data := struct {
		Companies        []Company         `json:"companies"`
		Users            []User            `json:"users"`
		ReferralRequests []ReferralRequest `json:"referralRequests"`
	}{}

	// Fetch companies
	companies, err := GetAllCompanies()
	if err != nil {
		log.Println("Error fetching companies:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data.Companies = companies

	// Fetch users
	users, err := GetAllUsers()
	if err != nil {
		log.Println("Error fetching users:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data.Users = users

	// Fetch referral requests
	referralRequests, err := GetAllReferralRequests()
	if err != nil {
		log.Println("Error fetching referral requests:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data.ReferralRequests = referralRequests

	// Encode the data as JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
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

func GetCompanyNameByID(companyID int) (string, error) {
	var companyName string
	err := db.QueryRow("SELECT name FROM companies WHERE id = $1", companyID).Scan(&companyName)
	if err != nil {
		return "", err
	}
	return companyName, nil
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

	// Check if the company exists
	var companyID int
	err := db.QueryRow("SELECT id FROM companies WHERE id = $1", user.CompanyID).Scan(&companyID)
	if err == sql.ErrNoRows {
		// Company does not exist, insert it
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

	// Now insert the user
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (email, username, password, role, company_id) VALUES ($1, $2, $3, $4, $5)",
		user.Email, user.Username, hashedPassword, user.Role, companyID)
	if err != nil {
		log.Println("Error inserting user:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Parse user details from request body
	var updatedUser User
	if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Only hash the password if it is updated
	if updatedUser.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updatedUser.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}
		updatedUser.Password = string(hashedPassword)
	}

	// Perform the update in the database
	_, err := db.Exec("UPDATE users SET email = $1, username = $2, password = $3, role = $4, company_id = $5 WHERE id = $6",
		updatedUser.Email, updatedUser.Username, updatedUser.Password, updatedUser.Role, updatedUser.CompanyID, updatedUser.ID)
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

func GetAuthenticatedUserData(r *http.Request) PageData {
	var pageData PageData
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		pageData.IsAuthenticated = false
		log.Println("No session cookie found:", err)
		return pageData
	}
	log.Println("Session cookie found:", sessionCookie.Value)
	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE session_id = $1 AND expires_at > NOW()", sessionCookie.Value).Scan(&userID)
	if err != nil {
		pageData.IsAuthenticated = false
		log.Println("Invalid session:", err)
		return pageData
	}
	var username, role string
	var companyID int
	err = db.QueryRow("SELECT username, role, company_id FROM users WHERE id = $1", userID).Scan(&username, &role, &companyID)
	if err != nil {
		pageData.IsAuthenticated = false
		log.Println("Error fetching user data:", err)
		return pageData
	}
	pageData.UserID = userID
	pageData.Username = username
	pageData.Role = role
	pageData.CompanyID = companyID
	pageData.IsAuthenticated = true
	return pageData
}

func GetAllCompanies() ([]Company, error) {
	var companies []Company

	rows, err := db.Query("SELECT id, name FROM companies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var company Company
		err := rows.Scan(&company.ID, &company.Name)
		if err != nil {
			return nil, err
		}
		companies = append(companies, company)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return companies, nil
}

func GetAllUsers() ([]User, error) {
	var users []User

	rows, err := db.Query("SELECT id, email, username, role, company_id FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.Role, &user.CompanyID)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func GetAllReferralRequests() ([]ReferralRequest, error) {
	var requests []ReferralRequest

	rows, err := db.Query(`
		SELECT rr.id, rr.title, rr.content, u.username, rr.referee_client, rr.referee_client_email, rr.created_at, rr.status, c.name 
		FROM referral_requests rr 
		JOIN users u ON rr.referrer_user_id = u.id 
		JOIN companies c ON rr.company_id = c.id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var request ReferralRequest
		err := rows.Scan(&request.ID, &request.Title, &request.Content, &request.Username, &request.RefereeClient, &request.RefereeClientEmail, &request.CreatedAt, &request.Status, &request.CompanyName)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return requests, nil
}

func GetReferralRequestsByCompanyID(companyID int) ([]ReferralRequest, error) {
	// Execute the SQL query to fetch referral requests
	rows, err := db.Query(`
        SELECT 
            referral_requests.id, 
            referral_requests.title, 
            referral_requests.content, 
            referral_requests.referrer_user_id, 
            referral_requests.company_id, 
            referral_requests.referee_client, 
            referral_requests.referee_client_email, 
            referral_requests.created_at, 
            referral_requests.status,
            users.username
        FROM 
            referral_requests
        JOIN 
            users ON referral_requests.referrer_user_id = users.id
        WHERE 
            referral_requests.company_id = $1`, companyID) // Use $1 placeholder for parameter
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []ReferralRequest
	for rows.Next() {
		var request ReferralRequest
		err := rows.Scan(&request.ID, &request.Title, &request.Content, &request.ReferrerUserID, &request.CompanyID, &request.RefereeClient, &request.RefereeClientEmail, &request.CreatedAt, &request.Status, &request.Username)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return requests, nil
}

func GetReferralRequestsByCompanyIDHandler(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user data from the request
	pageData := GetAuthenticatedUserData(r)

	// Check if the user is authenticated
	if !pageData.IsAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the companyID from the URL path parameters
	vars := mux.Vars(r)
	companyID, err := strconv.Atoi(vars["companyID"])
	if err != nil {
		http.Error(w, "Invalid company ID", http.StatusBadRequest)
		return
	}

	// Fetch referral requests for the specified company
	referralRequests, err := GetReferralRequestsByCompanyID(companyID)
	if err != nil {
		log.Println("Error fetching referral requests:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Encode referral requests data as JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(referralRequests)
}

func GetReferralRequestsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, title, content, username, referee_client, referee_client_email, created_at, status, company_name FROM referral_requests")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var requests []ReferralRequest
	for rows.Next() {
		var request ReferralRequest
		if err := rows.Scan(&request.ID, &request.Title, &request.Content, &request.Username, &request.RefereeClient, &request.RefereeClientEmail, &request.CreatedAt, &request.Status, &request.CompanyName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requests = append(requests, request)
	}

	if err := json.NewEncoder(w).Encode(requests); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
