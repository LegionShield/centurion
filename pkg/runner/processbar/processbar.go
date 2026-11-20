package processbar

type ProcessData struct {
	SuccessIndex  uint64
	SendIndex     uint64 // DNS queries sent successfully (at least one WritePacketData OK)
	AttemptIndex  uint64 // total WritePacketData calls (includes retries)
	QueueLength   int64
	RecvIndex     uint64
	FaildIndex    uint64
	Elapsed       int
}
type ProcessBar interface {
	WriteData(data *ProcessData)
	Close()
}
