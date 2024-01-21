package participant

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const idTag = "id"

type Participant struct {
	ID       uint16
	Email    string
	Name     string
	Surname  string
	Pronouns string
	City     string
	Birth    string
	Matches  []uint16
}

type Participants map[uint16]*Participant

func ConvertCSVData(pData [][]string) (Participants, error) {
	p := Participants{}
	for _, line := range pData {
		if strings.EqualFold(line[0], idTag) {
			continue
		}
		intID, err := strconv.Atoi(line[0])
		if err != nil {
			return nil, fmt.Errorf("error converting value '%s' to int", line[0])
		}

		id := uint16(intID)

		_, exists := p[id]
		// If the key exists
		if exists {
			return nil, fmt.Errorf("error converting participants data: id %d is duplicated", id)
		}

		p[id] = &Participant{
			ID:       uint16(id),
			Email:    line[1],
			Name:     line[2],
			Surname:  line[3],
			Pronouns: line[4],
			City:     line[5],
			Birth:    line[6],
		}
	}
	return p, nil
}

func (p *Participants) LoadMatches(mData [][]string) error {
	for _, line := range mData {
		intID, err := strconv.Atoi(line[0])
		if err != nil {
			return fmt.Errorf("error converting value '%s' to int", line[0])
		}

		id := uint16(intID)
		matches := []uint16{}

		for i := 1; i < len(line); i++ {
			if line[i] != "" {
				match, err := strconv.Atoi(line[i])
				if err != nil {
					return fmt.Errorf("error converting value '%s' to int", line[i])
				}
				matches = append(matches, uint16(match))
			}
		}

		participant, exists := (*p)[id]
		if !exists {
			return fmt.Errorf("participant with id %d does not exist", id)
		}
		participant.Matches = matches
	}

	return nil
}

func (p *Participant) CheckIfMatched(id uint16) bool {
	return slices.Contains(p.Matches, id)
}

func (p *Participants) ProcessMatches() {
	for _, participant := range *p {
		for i := range participant.Matches {
			if !(*p)[participant.Matches[i]].CheckIfMatched(participant.ID) {
				participant.Matches = remove(participant.Matches, i)
				i--
			}
		}
	}
}

func remove(s []uint16, i int) []uint16 {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}
