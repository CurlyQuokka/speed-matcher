package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/smtp"
	"strings"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
	"github.com/CurlyQuokka/speed-matcher/pkg/result"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
)

type Server struct {
	maxUploadSize  int64
	allowedDomains []string
	sec            *security.Security
}

type ToSend struct {
	From    string `json:"from"`
	Pass    string `json:"pass"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Content string `json:"content"`
	Otp     string `json:"otp"`
}

func New(maxUploadSize int64, allowedDomains []string, sec *security.Security) *Server {
	return &Server{
		maxUploadSize:  maxUploadSize,
		allowedDomains: allowedDomains,
		sec:            sec,
	}
}

func (s *Server) Serve(port string) error {
	sm := http.NewServeMux()
	sm.Handle("/", http.FileServer(http.Dir("frontend/")))
	sm.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("scripts"))))
	sm.HandleFunc("/result", s.UploadHandler)
	sm.HandleFunc("/mail", s.MailHandler)

	srv := http.Server{
		Addr:    ":" + port,
		Handler: sm,
	}

	if err := srv.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (s *Server) UploadHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadSize)
	if err = r.ParseMultipartForm(s.maxUploadSize); err != nil {
		http.Error(w, "the uploaded file is too big. Please choose an file that's less than 1MB in size", http.StatusBadRequest)
		return
	}

	fromEmail := r.FormValue("fromEmail")

	if len(s.allowedDomains) > 0 {
		isAuthorized, err := s.sec.IsEmailAuthorized(fromEmail)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !isAuthorized {
			http.Error(w, "address "+fromEmail+" is not authorized to use this service", http.StatusBadRequest)
			return
		}
	}

	passwordEmail := strings.ReplaceAll(r.FormValue("passwordEmail"), " ", "")

	pass, err := s.sec.Encrypt(passwordEmail)
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

	otp, err := s.sec.GenerateOTP()
	if err != nil {
		http.Error(w, "failed to generate OTP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	matchingResults := result.Result{
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

func (s *Server) MailHandler(w http.ResponseWriter, r *http.Request) {
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

	if !s.sec.CheckOTP(ts.Otp) {
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

	pass, err := s.sec.Decrypt(ts.Pass)
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
