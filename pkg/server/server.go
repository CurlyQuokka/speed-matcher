package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
	"github.com/CurlyQuokka/speed-matcher/pkg/result"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
)

const (
	defaultIdleTimeout       = 3 * time.Minute
	defaultReadTimeout       = 2 * time.Second
	defaultWriteTimeout      = 2 * time.Second
	defaultReadHeaderTimeout = 2 * time.Second
	defaultShutdownTimeout   = 5 * time.Second
)

type Server struct {
	maxUploadSize int64
	sec           *security.Security
	srv           *http.Server
}

type ToSend struct {
	From    string `json:"from"`
	Pass    string `json:"pass"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Content string `json:"content"`
	Otp     string `json:"otp"`
}

func New(maxUploadSize int64, sec *security.Security) *Server {
	return &Server{
		maxUploadSize: maxUploadSize,
		sec:           sec,
	}
}

func (s *Server) Serve(port string, errors chan<- error) {
	sm := http.NewServeMux()
	sm.Handle("/", http.FileServer(http.Dir("frontend/")))
	// sm.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("scripts"))))
	sm.HandleFunc("/result", s.UploadHandler)
	sm.HandleFunc("/mail", s.MailHandler)

	s.srv = &http.Server{
		Addr:              ":" + port,
		Handler:           sm,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}

	err := s.srv.ListenAndServe()
	errors <- err
}

func (s *Server) UploadHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	status, err := s.checkUploadHandlerSecurity(w, r)
	if err != nil {
		http.Error(w, "security issue: "+err.Error(), status)
		return
	}

	otp, err := s.sec.GenerateOTP()
	if err != nil {
		http.Error(w, "failed to generate OTP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	passwordEmail := strings.ReplaceAll(r.FormValue("passwordEmail"), " ", "")

	pass, err := s.sec.Encrypt(passwordEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	reader := csvreader.CSVReader{}

	participants, status, err := getParticipants(r, &reader)
	if err != nil {
		http.Error(w, "failed to get participants: "+err.Error(), status)
		return
	}

	status, err = getMatches(r, &reader)
	if err != nil {
		http.Error(w, "failed to get matches: "+err.Error(), status)
		return
	}

	err = participants.LoadMatches(reader.Data)
	if err != nil {
		http.Error(w, "failed to process matching data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	participants.ProcessMatches()

	fromEmail := r.FormValue("fromEmail")

	matchingResults := &result.Result{
		FromEmail:     fromEmail,
		PasswordEmail: pass,
		EventName:     r.FormValue("eventName"),
		Participants:  *participants,
		OTP:           otp,
	}

	if err = executeTemplate(w, matchingResults); err != nil {
		http.Error(w, "failed execute rtemplate: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func getParticipants(r *http.Request, reader *csvreader.CSVReader) (*participant.Participants, int, error) {
	participantsFile, _, err := r.FormFile("participants")
	if err != nil {
		return nil, http.StatusInternalServerError,
			fmt.Errorf("error reading participants form file: %w", err)
	}

	defer participantsFile.Close()

	err = reader.LoadDataFromFile(participantsFile, "participants")
	if err != nil {
		return nil, http.StatusInternalServerError,
			fmt.Errorf("failed to load participants data")
	}

	participants, err := participant.ConvertCSVData(reader.Data)
	if err != nil {
		return nil, http.StatusBadRequest,
			fmt.Errorf("failed to process participants data: %w", err)
	}

	return &participants, http.StatusOK, nil
}

func getMatches(r *http.Request, reader *csvreader.CSVReader) (int, error) {
	matchesFile, _, err := r.FormFile("matches")
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to load matching data: %w", err)
	}

	defer matchesFile.Close()

	err = reader.LoadDataFromFile(matchesFile, "matches")
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to load matching data: %w", err)
	}

	return http.StatusOK, nil
}

func executeTemplate(w http.ResponseWriter, matchingResults *result.Result) error {
	tmpl, err := template.New("result.gohtml").Funcs(template.FuncMap{
		"Deref": func(p *participant.Participant) participant.Participant {
			return *p
		},
	}).ParseFiles("templates/result.gohtml")
	if err != nil {
		return fmt.Errorf("failed to prepare matching template: %w", err)
	}

	err = tmpl.Execute(w, matchingResults)
	if err != nil {
		return fmt.Errorf("failed to execute result template: %w", err)
	}

	return nil
}

func (s *Server) MailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

func (s *Server) Shutdown() error {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		err := s.srv.Shutdown(ctx)
		if err != nil {
			return fmt.Errorf("error shutting down HTTP server: %w", err)
		}
	}
	return nil
}

func (s *Server) checkUploadHandlerSecurity(w http.ResponseWriter, r *http.Request) (int, error) {
	if r.Method != http.MethodPost {
		return http.StatusMethodNotAllowed, fmt.Errorf("method not allowed")
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadSize)
	if err := r.ParseMultipartForm(s.maxUploadSize); err != nil {
		return http.StatusBadRequest,
			fmt.Errorf("the uploaded file is too big (>%d)", s.maxUploadSize)
	}

	fromEmail := r.FormValue("fromEmail")

	isAuthorized, err := s.sec.IsEmailAuthorized(fromEmail)
	if err != nil {
		return http.StatusInternalServerError,
			fmt.Errorf("error checking email authorization: %w", err)
	}
	if !isAuthorized {
		http.Error(w, "address "+fromEmail+" is not authorized to use this service", http.StatusBadRequest)
		return http.StatusBadRequest,
			fmt.Errorf("address %s  is not authorized to use this service", fromEmail)
	}

	return http.StatusOK, nil
}
