package repository

import (
	"database/sql"

	"github.com/vibeswaf/waf/internal/model"
)


type UserRepository struct {
	db *sql.DB
}


func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}


func (r *UserRepository) FindByID(id int) (*model.User, error) {
	user := &model.User{}
	query := `
		SELECT id, username, password_hash, email, role, enabled, last_login, created_at, updated_at
		FROM users
		WHERE id = $1 AND enabled = true
	`
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Email,
		&user.Role,
		&user.Enabled,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) FindByUsername(username string) (*model.User, error) {
	user := &model.User{}
	query := `
		SELECT id, username, password_hash, email, role, enabled, last_login, created_at, updated_at
		FROM users
		WHERE username = $1 AND enabled = true
	`
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Email,
		&user.Role,
		&user.Enabled,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}


func (r *UserRepository) FindByUsernameOrEmail(usernameOrEmail string) (*model.User, error) {
	user := &model.User{}
	query := `
		SELECT id, username, password_hash, email, role, enabled, last_login, created_at, updated_at
		FROM users
		WHERE (username = $1 OR email = $1) AND enabled = true
	`
	err := r.db.QueryRow(query, usernameOrEmail).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Email,
		&user.Role,
		&user.Enabled,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}


func (r *UserRepository) Create(user *model.User) error {
	query := `
		INSERT INTO users (username, password_hash, email, role, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`
	return r.db.QueryRow(
		query,
		user.Username,
		user.PasswordHash,
		user.Email,
		user.Role,
		user.Enabled,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
}


func (r *UserRepository) UpdatePassword(userID int, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $1, updated_at = NOW()
		WHERE id = $2
	`
	_, err := r.db.Exec(query, passwordHash, userID)
	return err
}


func (r *UserRepository) UpdateLastLogin(userID int) error {
	query := `
		UPDATE users
		SET last_login = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(query, userID)
	return err
}


func (r *UserRepository) Exists(username string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`
	err := r.db.QueryRow(query, username).Scan(&exists)
	return exists, err
}


func (r *UserRepository) Count() (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM users`
	err := r.db.QueryRow(query).Scan(&count)
	return count, err
}
