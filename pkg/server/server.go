package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
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

	sessionCookieName = "session"
)

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:8080/callback-gl",
		Scopes:       []string{"https://www.googleapis.com/auth/gmail.send"},
		Endpoint:     google.Endpoint,
	}
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
	To      string `json:"to"`
	Subject string `json:"subject"`
	Content string `json:"content"`
	Otp     string `json:"otp"`
}

func New(maxUploadSize int64, sec *security.Security, certFile, keyFile string) (*Server, error) {
	key, err := security.GenerateSecret(64)
	if err != nil {
		return nil, fmt.Errorf("error generating secret for cookie store")
	}

	return &Server{
		maxUploadSize: maxUploadSize,
		sec:           sec,
		certFile:      certFile,
		keyFile:       keyFile,
		store:         sessions.NewCookieStore([]byte(key)),
	}, nil
}

func (s *Server) Serve(port string, errors chan<- error) {
	sm := http.NewServeMux()
	sm.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))
	sm.HandleFunc("/login", s.GoogleLoginHandler)
	sm.HandleFunc("/logout", s.LogoutHandler)
	sm.HandleFunc("/result", s.UploadHandler)
	sm.HandleFunc("/mail", s.MailHandler)
	sm.HandleFunc("/callback-gl", s.CallBackFromGoogle)
	sm.HandleFunc("/", s.FormHandler)

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
	emailTo := "To: " + ts.To + "\r\n"
	subject := "Subject: " + ts.Subject + "\n"
	msg := []byte(emailTo + subject + mime + "\n" + ts.Content)

	message := &gmail.Message{}
	message.Raw = base64.URLEncoding.EncodeToString(msg)

	if s.gmailSvc == nil {
		http.Error(w, "error while sending to: "+ts.To+" gmail service not initialized", http.StatusInternalServerError)
		return
	}
	if _, err := s.gmailSvc.Users.Messages.Send("me", message).Do(); err != nil {
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

	// fromEmail := r.FormValue("fromEmail")

	// isAuthorized, err := s.sec.IsEmailAuthorized(fromEmail)
	// if err != nil {
	// 	return http.StatusInternalServerError,
	// 		fmt.Errorf("error checking email authorization: %w", err)
	// }
	// if !isAuthorized {
	// 	return http.StatusBadRequest,
	// 		fmt.Errorf("address %s is not authorized to use this service", fromEmail)
	// }

	return http.StatusOK, nil
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
	URL, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		http.Error(w, "failed to parse: "+err.Error(), http.StatusInternalServerError)
		return
	}
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, sessionCookieName)
	if err != nil {
		http.Error(w, "failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsNew {
		id, err := s.sec.NewSession()
		if err != nil {
			http.Error(w, "failed to create new session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["id"] = id
		if err := session.Save(r, w); err != nil {
			http.Error(w, "failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	internalSession, err := s.sec.GetSessionByObject(session)
	if err != nil {
		http.Error(w, "getting internal session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if internalSession.Authorized {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	s.LoginHandler(w, r, oauthConfGl, internalSession.OAuthState)
}

var (
	ctx = context.Background()
)

func (s *Server) CallBackFromGoogle(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, sessionCookieName)
	if err != nil {
		http.Error(w, "failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	internalSession, err := s.sec.GetSessionByObject(session)
	if err != nil {
		http.Error(w, "trying to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if internalSession.Authorized {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	state := r.FormValue("state")
	if state != internalSession.OAuthState {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")

	if code == "" {
		reason := r.FormValue("error_reason")
		fmt.Println(reason)
		errorValue := r.FormValue("error")
		if reason == "user_denied" || errorValue == "access_denied" {
			http.Error(w, "No code returned from Google: user has denied permission", http.StatusBadRequest)
			return
		}
		http.Error(w, "No code returned from Google: "+errorValue, http.StatusBadRequest)
		return
	} else {
		token, err := oauthConfGl.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "OAuth exchange failed with "+err.Error(), http.StatusBadRequest)
			return
		}

		var tokenSource = oauthConfGl.TokenSource(context.Background(), token)

		s.gmailSvc, err = gmail.NewService(context.Background(), option.WithTokenSource(tokenSource))
		if err != nil {
			http.Error(w, "failed to create gmail client "+err.Error(), http.StatusBadRequest)
			return
		}

		internalSession.Authorized = true

		session.Save(r, w)

		if err != nil {
			http.Error(w, "failed to read body: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

func (s *Server) FormHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, sessionCookieName)
	if err != nil {
		http.Error(w, "failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsNew {
		id, err := s.sec.NewSession()
		if err != nil {
			http.Error(w, "failed to create new session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["id"] = id
		if err := session.Save(r, w); err != nil {
			http.Error(w, "failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	id, ok := session.Values["id"].(string)

	if !ok {
		http.Error(w, "failed to get session ID", http.StatusBadRequest)
		return
	}

	internalSession, err := s.sec.GetSession(id)
	if err != nil {
		http.Error(w, "failed to find session with ID", http.StatusBadRequest)
		return
	}

	if !internalSession.Authorized {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
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

func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, sessionCookieName)
	if err != nil {
		http.Error(w, "failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = -1

	s.store.Save(r, w, session)

	w.Write([]byte("Logged out"))
	return
}

func (s *Server) checkSession(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Get(r, sessionCookieName)
	if err != nil {
		http.Error(w, "failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsNew {
		id, err := s.sec.NewSession()
		if err != nil {
			http.Error(w, "failed to create new session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["id"] = id
		if err := session.Save(r, w); err != nil {
			http.Error(w, "failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	id, ok := session.Values["id"].(string)

	if !ok {
		http.Error(w, "failed to get session ID", http.StatusBadRequest)
		return
	}

	internalSession, err := s.sec.GetSession(id)
	if err != nil {
		http.Error(w, "failed to find session with ID", http.StatusBadRequest)
		return
	}

	if !internalSession.Authorized {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

}
