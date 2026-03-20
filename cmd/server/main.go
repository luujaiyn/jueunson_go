package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

func main() {
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	{
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}

			request.Username = strings.TrimSpace(request.Username)
			request.Name = strings.TrimSpace(request.Name)
			request.Email = strings.TrimSpace(request.Email)
			request.Phone = strings.TrimSpace(request.Phone)
			request.Password = strings.TrimSpace(request.Password)

			if request.Username == "" || request.Name == "" || request.Email == "" || request.Phone == "" || request.Password == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "all fields are required"})
				return
			}

			_, exists, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to check user"})
				return
			}
			if exists {
				c.JSON(http.StatusConflict, gin.H{"message": "username already exists"})
				return
			}

			user, err := store.createUser(request)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create user"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "user created",
				"user":    makeUserResponse(user),
			})
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			request.Username = strings.TrimSpace(request.Username)
			request.Password = strings.TrimSpace(request.Password)

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{"message": "logged out"})
		})

		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			deleted, err := store.deleteUserWithPassword(user.ID, strings.TrimSpace(request.Password))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to withdraw account"})
				return
			}
			if !deleted {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid password"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
		})
	}

	protected := router.Group("/api")
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "amount must be positive"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			updated, found, err := store.deposit(user.ID, request.Amount)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "deposit failed"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "deposit success",
				"user":    makeUserResponse(updated),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "amount must be positive"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			updated, found, enough, err := store.withdraw(user.ID, request.Amount)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "withdraw failed"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
				return
			}
			if !enough {
				c.JSON(http.StatusBadRequest, gin.H{"message": "insufficient balance"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "withdraw success",
				"user":    makeUserResponse(updated),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			request.ToUsername = strings.TrimSpace(request.ToUsername)

			if request.ToUsername == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "to_username is required"})
				return
			}
			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "amount must be positive"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if request.ToUsername == user.Username {
				c.JSON(http.StatusBadRequest, gin.H{"message": "cannot transfer to yourself"})
				return
			}

			fromUser, toUser, found, enough, err := store.transferByUsername(user.ID, request.ToUsername, request.Amount)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "transfer failed"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "target user not found"})
				return
			}
			if !enough {
				c.JSON(http.StatusBadRequest, gin.H{"message": "insufficient balance"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message":   "transfer success",
				"from_user": makeUserResponse(fromUser),
				"to_user":   makeUserResponse(toUser),
				"amount":    request.Amount,
			})
		})

		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			posts, err := store.listPosts()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load posts"})
				return
			}

			c.JSON(http.StatusOK, PostListResponse{Posts: posts})
		})

		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			request.Title = strings.TrimSpace(request.Title)
			request.Content = strings.TrimSpace(request.Content)
			if request.Title == "" || request.Content == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "title and content are required"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			post, err := store.createPost(user.ID, request.Title, request.Content)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create post"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "post created",
				"post":    post,
			})
		})

		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			postID := strings.TrimSpace(c.Param("id"))
			if postID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid post id"})
				return
			}

			post, found, err := store.getPostByID(postID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load post"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
				return
			}

			c.JSON(http.StatusOK, PostResponse{Post: post})
		})

		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			request.Title = strings.TrimSpace(request.Title)
			request.Content = strings.TrimSpace(request.Content)
			if request.Title == "" || request.Content == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "title and content are required"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			postID := strings.TrimSpace(c.Param("id"))
			if postID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid post id"})
				return
			}

			updated, found, err := store.updatePost(postID, request.Title, request.Content)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update post"})
				return
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "post updated",
				"post":    updated,
			})
		})

		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			postID := strings.TrimSpace(c.Param("id"))
			if postID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid post id"})
				return
			}

			deleted, err := store.deletePost(postID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete post"})
				return
			}
			if !deleted {
				c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "post deleted"})
		})
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
      SELECT id, username, name, email, phone, password, balance, is_admin
      FROM users
      WHERE username = ?
   `, strings.TrimSpace(username))

	var user User
	var id int64
	var isAdmin int64
	if err := row.Scan(&id, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}

	user.ID = uint(id)
	user.IsAdmin = isAdmin == 1
	return user, true, nil
}

func (s *Store) findUserByID(userID uint) (User, bool, error) {
	row := s.db.QueryRow(`
      SELECT id, username, name, email, phone, password, balance, is_admin
      FROM users
      WHERE id = ?
   `, userID)

	var user User
	var id int64
	var isAdmin int64
	if err := row.Scan(&id, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}

	user.ID = uint(id)
	user.IsAdmin = isAdmin == 1
	return user, true, nil
}

func (s *Store) createUser(request RegisterRequest) (User, error) {
	_, err := s.db.Exec(`
      INSERT INTO users (username, name, email, phone, password, balance, is_admin)
      VALUES (?, ?, ?, ?, ?, 0, 0)
   `, request.Username, request.Name, request.Email, request.Phone, request.Password)
	if err != nil {
		return User{}, err
	}

	user, ok, err := s.findUserByUsername(request.Username)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, errors.New("created user not found")
	}
	return user, nil
}

func (s *Store) deleteUserWithPassword(userID uint, password string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var currentPassword string
	if err := tx.QueryRow(`SELECT password FROM users WHERE id = ?`, userID).Scan(&currentPassword); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	if currentPassword != password {
		return false, nil
	}

	_, err = tx.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) deposit(userID uint, amount int64) (User, bool, error) {
	result, err := s.db.Exec(`UPDATE users SET balance = balance + ? WHERE id = ?`, amount, userID)
	if err != nil {
		return User{}, false, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return User{}, false, err
	}
	if rows == 0 {
		return User{}, false, nil
	}

	user, ok, err := s.findUserByID(userID)
	if err != nil {
		return User{}, false, err
	}
	if !ok {
		return User{}, false, nil
	}
	return user, true, nil
}

func (s *Store) withdraw(userID uint, amount int64) (User, bool, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, false, false, err
	}
	defer tx.Rollback()

	var balance int64
	if err := tx.QueryRow(`SELECT balance FROM users WHERE id = ?`, userID).Scan(&balance); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, false, nil
		}
		return User{}, false, false, err
	}

	if balance < amount {
		return User{}, true, false, nil
	}

	if _, err := tx.Exec(`UPDATE users SET balance = balance - ? WHERE id = ?`, amount, userID); err != nil {
		return User{}, false, false, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, false, false, err
	}

	user, ok, err := s.findUserByID(userID)
	if err != nil {
		return User{}, false, false, err
	}
	if !ok {
		return User{}, false, false, nil
	}

	return user, true, true, nil
}

func (s *Store) transferByUsername(fromID uint, toUsername string, amount int64) (User, User, bool, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, User{}, false, false, err
	}
	defer tx.Rollback()

	var fromBalance int64
	if err := tx.QueryRow(`SELECT balance FROM users WHERE id = ?`, fromID).Scan(&fromBalance); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, User{}, false, false, nil
		}
		return User{}, User{}, false, false, err
	}

	var toID int64
	if err := tx.QueryRow(`SELECT id FROM users WHERE username = ?`, toUsername).Scan(&toID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, User{}, false, false, nil
		}
		return User{}, User{}, false, false, err
	}

	if fromBalance < amount {
		return User{}, User{}, true, false, nil
	}

	if _, err := tx.Exec(`UPDATE users SET balance = balance - ? WHERE id = ?`, amount, fromID); err != nil {
		return User{}, User{}, false, false, err
	}
	if _, err := tx.Exec(`UPDATE users SET balance = balance + ? WHERE id = ?`, amount, toID); err != nil {
		return User{}, User{}, false, false, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, User{}, false, false, err
	}

	fromUser, ok, err := s.findUserByID(fromID)
	if err != nil {
		return User{}, User{}, false, false, err
	}
	if !ok {
		return User{}, User{}, false, false, nil
	}

	toUser, ok, err := s.findUserByID(uint(toID))
	if err != nil {
		return User{}, User{}, false, false, err
	}
	if !ok {
		return User{}, User{}, false, false, nil
	}

	return fromUser, toUser, true, true, nil
}

func (s *Store) listPosts() ([]PostView, error) {
	rows, err := s.db.Query(`
      SELECT p.id, p.title, p.content, p.owner_id, u.name, u.email, p.created_at, p.updated_at
      FROM posts p
      JOIN users u ON u.id = p.owner_id
      ORDER BY p.id DESC
   `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	posts := make([]PostView, 0)
	for rows.Next() {
		var post PostView
		var id int64
		var ownerID int64

		if err := rows.Scan(&id, &post.Title, &post.Content, &ownerID, &post.Author, &post.AuthorEmail, &post.CreatedAt, &post.UpdatedAt); err != nil {
			return nil, err
		}

		post.ID = uint(id)
		post.OwnerID = uint(ownerID)
		posts = append(posts, post)
	}

	return posts, rows.Err()
}

func (s *Store) getPostByID(postID string) (PostView, bool, error) {
	row := s.db.QueryRow(`
      SELECT p.id, p.title, p.content, p.owner_id, u.name, u.email, p.created_at, p.updated_at
      FROM posts p
      JOIN users u ON u.id = p.owner_id
      WHERE p.id = ?
   `, postID)

	var post PostView
	var id int64
	var ownerID int64
	if err := row.Scan(&id, &post.Title, &post.Content, &ownerID, &post.Author, &post.AuthorEmail, &post.CreatedAt, &post.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PostView{}, false, nil
		}
		return PostView{}, false, err
	}

	post.ID = uint(id)
	post.OwnerID = uint(ownerID)
	return post, true, nil
}

func (s *Store) createPost(ownerID uint, title, content string) (PostView, error) {
	now := time.Now().Format(time.RFC3339)

	result, err := s.db.Exec(`
      INSERT INTO posts (title, content, owner_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
   `, title, content, ownerID, now, now)
	if err != nil {
		return PostView{}, err
	}

	postID, err := result.LastInsertId()
	if err != nil {
		return PostView{}, err
	}

	user, ok, err := s.findUserByID(ownerID)
	if err != nil {
		return PostView{}, err
	}
	if !ok {
		return PostView{}, errors.New("user not found")
	}

	return PostView{
		ID:          uint(postID),
		Title:       title,
		Content:     content,
		OwnerID:     ownerID,
		Author:      user.Name,
		AuthorEmail: user.Email,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (s *Store) updatePost(postID string, title, content string) (PostView, bool, error) {
	now := time.Now().Format(time.RFC3339)

	result, err := s.db.Exec(`
      UPDATE posts
      SET title = ?, content = ?, updated_at = ?
      WHERE id = ?
   `, title, content, now, postID)
	if err != nil {
		return PostView{}, false, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return PostView{}, false, err
	}
	if rows == 0 {
		return PostView{}, false, nil
	}

	post, found, err := s.getPostByID(postID)
	if err != nil {
		return PostView{}, false, err
	}
	if !found {
		return PostView{}, false, nil
	}

	return post, true, nil
}

func (s *Store) deletePost(postID string) (bool, error) {
	result, err := s.db.Exec(`DELETE FROM posts WHERE id = ?`, postID)
	if err != nil {
		return false, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		return false, nil
	}

	return true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

func registerStaticRoutes(router *gin.Engine) {
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
