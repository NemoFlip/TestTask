package service

import (
	"fmt"
	"gopkg.in/gomail.v2"
)

type MailSender struct {
	FromEmail string
	ToEmail   string
	Message   string
	IpAddr    string
}

func (ms *MailSender) SendMessage() error {
	message := gomail.NewMessage()
	message.SetHeader("From", ms.FromEmail)
	message.SetHeader("To", ms.ToEmail)
	message.SetHeader("Subject", "Suspicious activity")
	htmlBody := fmt.Sprintf(`
		Hello! <br><br>
		Attempt of logging in from suspicious IP address: <b>%s</b>.
	`, ms.IpAddr)
	message.SetBody("text/html", htmlBody)

	dialer := gomail.NewDialer("smtp.gmail.com", 587, "user", "123456")

	if err := dialer.DialAndSend(message); err != nil {
		return fmt.Errorf("unable to send message: %s", err)
	}
	return nil
}
