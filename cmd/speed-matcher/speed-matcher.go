package main

import (
	"fmt"
	"log"
	"os"

	"github.com/CurlyQuokka/speed-matcher/pkg/csvreader"
	"github.com/CurlyQuokka/speed-matcher/pkg/participant"
)

func main() {
	participantsReader := csvreader.CSVReader{}
	err := participantsReader.LoadData(os.Args[1])
	if err != nil {
		log.Fatalf("error reading participants: %s", err.Error())
	}

	matchesReader := csvreader.CSVReader{}
	err = matchesReader.LoadData(os.Args[2])
	if err != nil {
		log.Fatalf("error reading matches: %s", err.Error())
	}

	fmt.Println("Participants info:")
	for _, line := range participantsReader.Data {
		fmt.Println(line)
	}
	fmt.Println()
	fmt.Println("Matches:")
	for _, line := range matchesReader.Data {
		fmt.Println(line)
	}

	fmt.Println()
	participants, err := participant.ConvertCSVData(participantsReader.Data)
	if err != nil {
		log.Fatalf("error converting CSV data to participants: %s", err.Error())
		os.Exit(3)
	}

	for _, p := range participants {
		fmt.Println(*p)
	}

	err = participants.LoadMatches(matchesReader.Data)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println()

	fmt.Println()
	for _, p := range participants {
		fmt.Println(*p)
	}

	participants.ProcessMatches()

	fmt.Println()
	for _, p := range participants {
		fmt.Println(*p)
	}
}
