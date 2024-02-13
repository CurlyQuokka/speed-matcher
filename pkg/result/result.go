package result

import "github.com/CurlyQuokka/speed-matcher/pkg/participant"

type Result struct {
	FromEmail    string
	EventName    string
	Participants participant.Participants
	OTP          string
}
