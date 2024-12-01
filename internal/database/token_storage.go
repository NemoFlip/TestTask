package database

import (
	"TestTask/internal/entity"
	"database/sql"
	"errors"
	"fmt"
)

type RefreshStorage struct {
	DB *sql.DB
}

func NewRefreshStorage(db *sql.DB) *RefreshStorage {
	return &RefreshStorage{DB: db}
}

func (rs *RefreshStorage) Post(refreshToken entity.RefreshToken) error {
	query := "INSERT INTO refresh_tokens (user_id, refresh_token, expires_at) VALUES ($1, $2, $3)"

	result, err := rs.DB.Exec(query, refreshToken.UserID, refreshToken.RefreshToken, refreshToken.ExpiresAT)
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

func (rs *RefreshStorage) Get(userID string) (*entity.RefreshToken, error) {
	query := "SELECT id, user_id, refresh_token, expires_at FROM refresh_tokens WHERE user_id = $1"

	row := rs.DB.QueryRow(query, userID)
	var tokenFromDB entity.RefreshToken
	err := row.Scan(&tokenFromDB.ID, &tokenFromDB.UserID, &tokenFromDB.RefreshToken, &tokenFromDB.ExpiresAT)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("there is no rows with passed user id: %w", err)
		}
		return nil, fmt.Errorf("unable to scan token from selected row: %w", err)
	}
	return &tokenFromDB, nil
}

func (rs *RefreshStorage) Delete(userID string) error {
	query := "DELETE FROM refresh_tokens WHERE user_id = $1"

	result, err := rs.DB.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("unable to delete token by user_id(%s): %s", userID, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("unable to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows were deleted for user_id(%s)", userID)
	}

	return nil
}
