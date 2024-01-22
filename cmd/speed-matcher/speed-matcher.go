package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
)

type MatchingResults struct {
	EventName    string
	Participants participant.Participants
}

func main() {
	fs := http.FileServer(http.Dir("./frontend"))
	http.Handle("/", fs)

	http.HandleFunc("/result", uploadHandler)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

const MAX_UPLOAD_SIZE = 1024 * 1024 // 1MB

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)
	if err := r.ParseMultipartForm(MAX_UPLOAD_SIZE); err != nil {
		http.Error(w, "The uploaded file is too big. Please choose an file that's less than 1MB in size", http.StatusBadRequest)
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
		http.Error(w, "Failed to load participants data", http.StatusInternalServerError)
	}

	participants, err := participant.ConvertCSVData(reader.Data)
	if err != nil {
		http.Error(w, "Failed to load process participants data", http.StatusInternalServerError)
	}

	matchesFile, _, err := r.FormFile("matches")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	defer participantsFile.Close()

	err = reader.LoadDataFromFile(matchesFile, "matches")
	if err != nil {
		http.Error(w, "Failed to load matching data", http.StatusInternalServerError)
	}

	err = participants.LoadMatches(reader.Data)
	if err != nil {
		http.Error(w, "Failed to load process matching data", http.StatusInternalServerError)
	}

	participants.ProcessMatches()

	matchingResults := MatchingResults{
		EventName:    r.FormValue("eventName"),
		Participants: participants,
	}

	tmpl, err := template.New("result.gohtml").Funcs(template.FuncMap{
		"Deref": func(p *participant.Participant) participant.Participant {
			return *p
		},
	}).ParseFiles("templates/result.gohtml")
	if err != nil {
		http.Error(w, "Failed to prepare matching template", http.StatusInternalServerError)
	}

	err = tmpl.Execute(w, matchingResults)
	if err != nil {
		http.Error(w, "Failed to execute result template", http.StatusInternalServerError)
	}
}
