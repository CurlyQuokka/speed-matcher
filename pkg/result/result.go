package result

import "github.com/CurlyQuokka/speed-matcher/pkg/participant"

type Result struct {
	EventName    string
	Participants participant.Participants
}
