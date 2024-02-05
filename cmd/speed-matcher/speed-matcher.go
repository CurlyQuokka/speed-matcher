package main

import (
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
	. "github.com/CurlyQuokka/speed-matcher/pkg/result"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
)

const (
	DEF_MAX_UPLOAD_SIZE = 1024 * 1024 // 1MB
	DEF_PORT            = "8080"

	MAX_UPLOAD_SIZE_ENV = "MATCHER_MAX_UPLOAD_SIZE"
	PORT_ENV            = "MATCHER_PORT"
	SECRET_ENV          = "MATCHER_SECRET"
	SECRET_LENGTH_ENV   = "MATCHER_SECRET_LENGTH"
	DOMAINS_ENV         = "MATCHER_DOMAINS"
)

var (
	maxUploadSize int64
	secret        string
	port          = DEF_PORT
	cBlock        cipher.Block
	sec           *security.Security

	defaultSecretLength = 16
	domains             []string
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err = r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "the uploaded file is too big. Please choose an file that's less than 1MB in size", http.StatusBadRequest)
		return
	}

	fromEmail := r.FormValue("fromEmail")

	if len(domains) > 0 {
		validEmail := false
		for _, domain := range domains {
			domainRegex := "^[\\w-\\.]+@" + strings.ReplaceAll(domain, ".", "\\.")
			fmt.Println(domainRegex)
			r, err := regexp.Compile(domainRegex)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if r.MatchString(fromEmail) {
				validEmail = true
				break
			}
		}
		if !validEmail {
			http.Error(w, "email "+fromEmail+" is not allowed", http.StatusBadRequest)
			return
		}
	}

	passwordEmail := strings.ReplaceAll(r.FormValue("passwordEmail"), " ", "")

	pass, err := sec.Encrypt(passwordEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	participantsFile, _, err := r.FormFile("participants")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defer participantsFile.Close()

	reader := csvreader.CSVReader{}

	err = reader.LoadDataFromFile(participantsFile, "participants")
	if err != nil {
		http.Error(w, "failed to load participants data", http.StatusInternalServerError)
		return
	}

	participants, err := participant.ConvertCSVData(reader.Data)
	if err != nil {
		http.Error(w, "failed to process participants data: "+err.Error(), http.StatusBadRequest)
		return
	}

	matchesFile, _, err := r.FormFile("matches")
	if err != nil {
		http.Error(w, "filed to load matching data:"+err.Error(), http.StatusInternalServerError)
		return
	}

	defer participantsFile.Close()

	err = reader.LoadDataFromFile(matchesFile, "matches")
	if err != nil {
		http.Error(w, "failed to load matching data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = participants.LoadMatches(reader.Data)
	if err != nil {
		http.Error(w, "failed to process matching data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	participants.ProcessMatches()

	otp, err := sec.GenerateOTP()
	if err != nil {
		http.Error(w, "failed to generate OTP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	matchingResults := Result{
		FromEmail:     fromEmail,
		PasswordEmail: pass,
		EventName:     r.FormValue("eventName"),
		Participants:  participants,
		OTP:           otp,
	}

	tmpl, err := template.New("result.gohtml").Funcs(template.FuncMap{
		"Deref": func(p *participant.Participant) participant.Participant {
			return *p
		},
	}).ParseFiles("templates/result.gohtml")
	if err != nil {
		http.Error(w, "failed to prepare matching template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, matchingResults)
	if err != nil {
		http.Error(w, "failed to execute result template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

type ToSend struct {
	From    string `json:"from"`
	Pass    string `json:"pass"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Content string `json:"content"`
	Otp     string `json:"otp"`
}

func mailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ts ToSend
	err := json.NewDecoder(r.Body).Decode(&ts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !sec.CheckOTP(ts.Otp) {
		http.Error(w, "OTP expired", http.StatusBadRequest)
		return
	}

	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	msg := "From: Stowarzyszenie Lambda Szczecin\n" +
		"To: " + ts.To + "\n" +
		"Subject: " + ts.Subject + "\n" +
		mime + ts.Content

	smtpGmail := "smtp.gmail.com"
	server := smtpGmail + ":587"

	pass, err := sec.Decrypt(ts.Pass)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	auth := smtp.PlainAuth("Stowarzyszenie Lambda Szczecin", ts.From, pass, smtpGmail)

	if err := smtp.SendMail(server, auth, ts.From, []string{ts.To}, []byte(msg)); err != nil {
		http.Error(w, "Error while sending to: "+ts.To+" "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	var err error

	secret = os.Getenv(SECRET_ENV)
	if secret == "" {
		secretLength := defaultSecretLength
		secretLengthEnv := os.Getenv(SECRET_LENGTH_ENV)
		if secretLengthEnv != "" {
			secretLength, err = strconv.Atoi(secretLengthEnv)
			if err != nil {
				log.Fatalf("cannot convert secret length of %s to integer", secretLengthEnv)
			}
		}
		secret, err = security.GenerateSecret(secretLength)
		if err != nil {
			log.Fatalf("cannot generate secret %s", err.Error())
		}
	}

	otpWatchQuit := make(chan bool)
	defer close(otpWatchQuit)

	sec, err = security.New(secret, otpWatchQuit)
	if err != nil {
		log.Fatalf("cannot create security module: %s", err.Error())
	}

	maxUploadSize = DEF_MAX_UPLOAD_SIZE
	maxUploadSizeEnv := os.Getenv(MAX_UPLOAD_SIZE_ENV)
	if maxUploadSizeEnv != "" {
		maxUploadSize, err = strconv.ParseInt(maxUploadSizeEnv, 10, 64)
		if err != nil {
			log.Fatal(err)
		}
	}

	portEnv := os.Getenv(PORT_ENV)
	if portEnv != "" {
		port = portEnv
	}

	domainString := os.Getenv(DOMAINS_ENV)
	if domainString != "" {
		domains = strings.Split(domainString, ",")
	}

	http.Handle("/", http.FileServer(http.Dir("frontend/")))

	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("scripts"))))

	http.HandleFunc("/result", uploadHandler)
	http.HandleFunc("/mail", mailHandler)

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal(err)
	}

	otpWatchQuit <- true
}
