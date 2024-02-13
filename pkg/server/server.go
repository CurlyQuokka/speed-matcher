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

	"github.com/CurlyQuokka/speed-matcher/pkg/config"
	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
	"github.com/CurlyQuokka/speed-matcher/pkg/result"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
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
	key64             = 64
)

type Server struct {
	cfg      *config.Config
	sec      *security.Security
	srv      *http.Server
	gmailSvc *gmail.Service
	store    *sessions.CookieStore
}

type ToSend struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Content string `json:"content"`
	Otp     string `json:"otp"`
}

func New(sec *security.Security, cfg *config.Config) (*Server, error) {
	var err error
	if cfg.CookieStoreKey == "" {
		cfg.CookieStoreKey, err = security.GenerateSecret(key64)
		fmt.Println(cfg.CookieStoreKey)
		if err != nil {
			return nil, fmt.Errorf("error generating secret for cookie store")
		}
	}

	return &Server{
		cfg:   cfg,
		sec:   sec,
		store: sessions.NewCookieStore([]byte(cfg.CookieStoreKey)),
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
	if s.cfg.CertFile != "" {
		err = s.srv.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
	} else {
		err = s.srv.ListenAndServe()
	}
	errors <- err
}

func (s *Server) UploadHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	session, err := s.checkSession(w, r)
	if err != nil {
		http.Error(w, "upload error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !session.Authorized {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

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

	// passwordEmail := strings.ReplaceAll(r.FormValue("passwordEmail"), " ", "")

	// pass, err := s.sec.Encrypt(passwordEmail)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

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
		FromEmail:    fromEmail,
		EventName:    r.FormValue("eventName"),
		Participants: *participants,
		OTP:          otp,
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
	session, err := s.checkSession(w, r)
	if err != nil {
		http.Error(w, "mailer error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !session.Authorized {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ts ToSend
	err = json.NewDecoder(r.Body).Decode(&ts)
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
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadSize)
	if err := r.ParseMultipartForm(s.cfg.MaxUploadSize); err != nil {
		return http.StatusBadRequest,
			fmt.Errorf("the uploaded file is too big (>%d)", s.cfg.MaxUploadSize)
	}

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
	session, err := s.checkSession(w, r)
	if err != nil {
		http.Error(w, "login error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if session.Authorized {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	s.LoginHandler(w, r, s.cfg.OAuth2Config, session.OAuthState)
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
		token, err := s.cfg.OAuth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "OAuth exchange failed with "+err.Error(), http.StatusBadRequest)
			return
		}

		var tokenSource = s.cfg.OAuth2Config.TokenSource(context.Background(), token)

		s.gmailSvc, err = gmail.NewService(ctx, option.WithTokenSource(tokenSource))
		if err != nil {
			http.Error(w, "failed to create gmail client "+err.Error(), http.StatusBadRequest)
			return
		}

		internalSession.Authorized = true

		if err = session.Save(r, w); err != nil {
			if internalErr := s.sec.DeleteSessionByObject(session); internalErr != nil {
				http.Error(w, "failed to delete internal session: "+err.Error(), http.StatusInternalServerError)
			}
			http.Error(w, "failed to save session: "+err.Error(), http.StatusInternalServerError)
			session.Options.MaxAge = -1
			_ = session.Save(r, w)
			return
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}

func (s *Server) FormHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.checkSession(w, r)
	if err != nil {
		if strings.Contains(err.Error(), "error getting internal session") {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "error creating session: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if !session.Authorized {
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

	if err = session.Save(r, w); err != nil {
		http.Error(w, "failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err = s.sec.DeleteSessionByObject(session); err != nil {
		http.Error(w, "failed to delete internal session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err = w.Write([]byte("Logged out")); err != nil {
		http.Error(w, "failed to write response: "+err.Error(), http.StatusInternalServerError)
	}
	return
}

func (s *Server) checkSession(w http.ResponseWriter, r *http.Request) (*security.Session, error) {
	session, err := s.store.Get(r, sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var id string
	var ok bool
	if session.IsNew {
		id, err = s.sec.NewSession()
		if err != nil {
			return nil, fmt.Errorf("failed to create internal session: %w", err)
		}
		session.Values["id"] = id

		if err := session.Save(r, w); err != nil {
			s.sec.DeleteSession(id)
			return nil, fmt.Errorf("failed to save session: %w", err)
		}
	} else {
		id, ok = session.Values["id"].(string)
		if !ok {
			session.Options.MaxAge = -1
			if err = session.Save(r, w); err != nil {
				return nil, fmt.Errorf("failed to save session: %w", err)
			}
			return nil, fmt.Errorf("error getting ID from session cookie")
		}
	}

	internalSession, err := s.sec.GetSession(id)
	if err != nil {
		session.Options.MaxAge = -1
		if err = session.Save(r, w); err != nil {
			return nil, fmt.Errorf("failed to save session: %w", err)
		}
		return nil, fmt.Errorf("error getting internal session: %w", err)
	}

	return internalSession, nil
}
