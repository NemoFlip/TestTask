package database

import (
	"database/sql"
	"fmt"
)

type RefreshStorage struct {
	DB *sql.DB
}

func NewRefreshStorage(db *sql.DB) *RefreshStorage {
	return &RefreshStorage{DB: db}
}

func (ts *RefreshStorage) Post(userID string, hashedToken string) error {
	query := "INSERT INTO refresh_tokens (user_id, refresh_token) VALUES ($1, $2)"

	result, err := ts.DB.Exec(query, userID, hashedToken)
	if err != nil {
		return fmt.Errorf("unable to insert token: %s", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("unable to get affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("zero rows were inserted")
	}
	return nil
}
