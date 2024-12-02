package entity

import "time"

type RefreshToken struct {
	ID           int       `json:"id"`
	UserID       string    `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAT    time.Time `json:"expires_at"`
}
