package slhdsa

// For pre-hashed signatures where the message was hashed externally, use
// [NewPreHashedMessage] to pass the concatenated OID and digest to be signed.
func NewPreHashedMessage(msg []byte) *Message { return &Message{msg, 1} }
