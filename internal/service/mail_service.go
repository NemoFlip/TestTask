package service

import (
	"fmt"
	"net/smtp"
	"os"
)

type MailSender struct {
	host     string
	port     string
	password string
	email    string
}

func NewMailSender() *MailSender {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	password := os.Getenv("SMTP_PASSWORD")
	email := os.Getenv("FROM_EMAIL")
	mailSender := MailSender{
		host:     host,
		port:     port,
		password: password,
		email:    email,
	}
	if host == "" || port == "" || password == "" || email == "" {
		return nil
	}
	return &mailSender
}

func (ms *MailSender) SendMessage(ipAddr string) error {
	auth := smtp.PlainAuth(
		"",
		ms.email,
		ms.password,
		ms.host,
	)
	toEmail := "clashtvink65@gmail.com"
	msg := fmt.Sprintf("Hello!\nAttempt of logging in from suspicious IP address: %s.", ipAddr)
	htmlBody := fmt.Sprintf("To: %s\nSubject:Warning\n%s", toEmail, msg)

	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", ms.host, ms.port),
		auth,
		"artgamer3163@gmail.com",
		[]string{toEmail},
		[]byte(htmlBody),
	)
	if err != nil {
		return fmt.Errorf("unable to send a mail: %s", err)
	}

	return nil
}
