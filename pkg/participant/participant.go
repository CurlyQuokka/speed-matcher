package participant

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	idTag      = "id"
	columnsNum = 8
)

type Participant struct {
	ID       uint16
	Email    string
	Consent  string
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
	for _, data := range pData {
		if len(data) != columnsNum {
			return nil, fmt.Errorf("error while converting CSV data - malformed file (number of columns is %d instead of %d)", columnsNum, len(data))
		}
		if strings.EqualFold(data[0], idTag) {
			continue
		}
		intID, err := strconv.Atoi(data[0])
		if err != nil {
			return nil, fmt.Errorf("error converting value '%s' to int", data[0])
		}

		id := uint16(intID)

		_, exists := p[id]
		// If the key exists
		if exists {
			return nil, fmt.Errorf("error converting participants data: id %d is duplicated", id)
		}

		p[id] = &Participant{
			ID:       id,
			Email:    data[1],
			Consent:  data[2],
			Name:     data[3],
			Surname:  data[4],
			Pronouns: data[5],
			City:     data[6],
			Birth:    data[7],
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
		for i := 0; i < len(participant.Matches); i++ {
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
