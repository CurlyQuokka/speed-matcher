package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
	"github.com/CurlyQuokka/speed-matcher/pkg/result"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	defaultIdleTimeout       = 3 * time.Minute
	defaultReadTimeout       = 2 * time.Second
	defaultWriteTimeout      = 2 * time.Second
	defaultReadHeaderTimeout = 2 * time.Second
	DefaultShutdownTimeout   = 5 * time.Second
)

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:8080/callback-gl",
		Scopes:       []string{"https://www.googleapis.com/auth/gmail.send"},
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGl = "mystate42"
)

type Server struct {
	maxUploadSize int64
	sec           *security.Security
	srv           *http.Server
	certFile      string
	keyFile       string
	gmailSvc      *gmail.Service
	store         *sessions.CookieStore
}

type ToSend struct {
	From    string `json:"from"`
	Pass    string `json:"pass"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Content string `json:"content"`
	Otp     string `json:"otp"`
}

func New(maxUploadSize int64, sec *security.Security, certFile, keyFile string) *Server {
	key := []byte("super-secret-key")
	return &Server{
		maxUploadSize: maxUploadSize,
		sec:           sec,
		certFile:      certFile,
		keyFile:       keyFile,
		store:         sessions.NewCookieStore(key),
	}
}

func (s *Server) Serve(port string, errors chan<- error) {
	sm := http.NewServeMux()
	sm.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("frontend/"))))
	sm.HandleFunc("/", s.GoogleLoginHandler)
	sm.HandleFunc("/result", s.UploadHandler)
	sm.HandleFunc("/mail", s.MailHandler)
	sm.HandleFunc("/callback-gl", s.CallBackFromGoogle)
	sm.HandleFunc("/form", s.FormHandler)

	s.srv = &http.Server{
		Addr:              ":" + port,
		Handler:           sm,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}

	var err error
	if s.certFile != "" {
		err = s.srv.ListenAndServeTLS(s.certFile, s.keyFile)
	} else {
		err = s.srv.ListenAndServe()
	}
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

	// msg := "From: Stowarzyszenie Lambda Szczecin\n" +
	// 	"To: " + ts.To + "\n" +
	// 	"Subject: " + ts.Subject + "\n" +
	// 	mime + ts.Content

	// emailFrom := "From: Stowarzyszenie Lambda Szczecin\n"
	emailTo := "To: " + ts.To + "\r\n"
	subject := "Subject: " + ts.Subject + "\n"

	msg := []byte(emailTo + subject + mime + "\n" + ts.Content)

	// smtpGmail := "smtp.gmail.com"
	// server := smtpGmail + ":587"

	// pass, err := s.sec.Decrypt(ts.Pass)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// auth := smtp.PlainAuth("Stowarzyszenie Lambda Szczecin", ts.From, pass, smtpGmail)

	// if err := smtp.SendMail(server, auth, ts.From, []string{ts.To}, []byte(msg)); err != nil {
	// 	http.Error(w, "error while sending to: "+ts.To+" "+err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	var message gmail.Message

	message.Raw = base64.URLEncoding.EncodeToString(msg)

	if s.gmailSvc == nil {
		http.Error(w, "error while sending to: "+ts.To+" gmail service not initialized", http.StatusInternalServerError)
		return
	}
	if _, err := s.gmailSvc.Users.Messages.Send("me", &message).Do(); err != nil {
		http.Error(w, "error while sending to: "+ts.To+" "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) Shutdown() error {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultShutdownTimeout)
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
		return http.StatusBadRequest,
			fmt.Errorf("address %s is not authorized to use this service", fromEmail)
	}

	return http.StatusOK, nil
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
	URL, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		http.Error(w, "failed to parse: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("url: %s\n", URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	fmt.Printf("url param: %s\n", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {

	session, err := s.store.Get(r, "cookie-name")
	if err != nil {
		fmt.Printf("Failed to get session: %v", err)
	}

	if !session.IsNew {
		fmt.Println("not new")
		http.Redirect(w, r, "/form", http.StatusTemporaryRedirect)
	}

	s.LoginHandler(w, r, oauthConfGl, oauthStateStringGl)
}

var (
	ctx = context.Background()
)

func (s *Server) CallBackFromGoogle(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Callback-gl..")

	session, err := s.store.Get(r, "cookie-name")
	if err != nil {
		fmt.Printf("Failed to get session: %v", err)
	}

	if !session.IsNew {
		fmt.Println("not new")
		http.Redirect(w, r, "/form", http.StatusTemporaryRedirect)
	}

	fmt.Println("new")

	state := r.FormValue("state")
	fmt.Println(state)
	if state != oauthStateStringGl {
		fmt.Println("invalid oauth state, expected " + oauthStateStringGl + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	fmt.Println(code)

	if code == "" {
		fmt.Println("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {

		token, err := oauthConfGl.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "oauthConfGl.Exchange() failed with "+err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println("TOKEN>> AccessToken>> " + token.AccessToken)
		fmt.Println("TOKEN>> Expiration Time>> " + token.Expiry.String())
		fmt.Println("TOKEN>> RefreshToken>> " + token.RefreshToken)

		var tokenSource = oauthConfGl.TokenSource(context.Background(), token)

		s.gmailSvc, err = gmail.NewService(context.Background(), option.WithTokenSource(tokenSource))
		if err != nil {
			log.Printf("Unable to retrieve Gmail client: %v", err)
		}
		fmt.Println("create gmail")

		session.Values["authenticated"] = true
		session.Save(r, w)

		fmt.Println("stored session")

		// c := oauthConfGl.Client(ctx, token)
		// r, err := c.Get("http://localhost:8080/form")
		// if err != nil {
		// 	log.Printf("failed to get form: %v", err)
		// }

		val := []byte{}
		_, err = r.Body.Read(val)

		if err != nil {
			log.Printf("Unable to read body: %v", err)
		}

		http.Redirect(w, r, "/form", http.StatusTemporaryRedirect)
		// s.FormHandler(w, r)
		// _, err = w.Write(val)
		// if err != nil {
		// 	log.Printf("Unable to write body: %v", err)
		// }

		return
	}
}

func (s *Server) FormHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("got request")
	session, err := s.store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("%t", session.IsNew)

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile("frontend/index.html")
	if err != nil {
		http.Error(w, "error reading file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = w.Write(data)
	if err != nil {
		http.Error(w, "error writing response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
