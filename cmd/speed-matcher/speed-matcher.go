package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
	. "github.com/CurlyQuokka/speed-matcher/pkg/result"
)

const (
	DEF_MAX_UPLOAD_SIZE = 1024 * 1024 // 1MB
	DEF_PORT            = "8080"

	MAX_UPLOAD_SIZE_ENV = "MATCHER_MAX_UPLOAD_SIZE"
	PORT_ENV            = "MATCHER_PORT"
)

var (
	maxUploadSize int64
	port          = DEF_PORT
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "the uploaded file is too big. Please choose an file that's less than 1MB in size", http.StatusBadRequest)
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

	matchingResults := Result{
		EventName:    r.FormValue("eventName"),
		Participants: participants,
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

func main() {
	var err error
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

	fs := http.FileServer(http.Dir("./frontend"))
	http.Handle("/", fs)

	http.HandleFunc("/result", uploadHandler)

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
