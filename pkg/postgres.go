package pkg

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"os"
)

func PostgresConnect() (*sql.DB, error) {
	postgresUser := os.Getenv("POSTGRES_USER")
	postgresPassword := os.Getenv("POSTGRES_PASSWORD")
	postgresDatabase := os.Getenv("POSTGRES_DB")
	if postgresUser == "" || postgresPassword == "" || postgresDatabase == "" {
		return nil, fmt.Errorf("unable to get environment variables for database connection")
	}
	dataSourceName := fmt.Sprintf("host=postgres port=5432 user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresPassword, postgresDatabase)
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping the database: %w", err)
	}
	return db, nil
}
