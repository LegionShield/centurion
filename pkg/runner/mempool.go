package runner

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MemoryPool struct {
	dnsPool      sync.Pool
	bufPool      sync.Pool
	questionPool sync.Pool
	answerPool   sync.Pool
}

var GlobalMemPool = NewMemoryPool()

func NewMemoryPool() *MemoryPool {
	return &MemoryPool{
		dnsPool: sync.Pool{
			New: func() interface{} {
				return &layers.DNS{
					Questions: make([]layers.DNSQuestion, 0, 1),
					Answers:   make([]layers.DNSResourceRecord, 0, 4),
				}
			},
		},
		bufPool: sync.Pool{
			New: func() interface{} {
				return gopacket.NewSerializeBuffer()
			},
		},
		questionPool: sync.Pool{
			New: func() interface{} {
				return make([]layers.DNSQuestion, 0, 1)
			},
		},
		answerPool: sync.Pool{
			New: func() interface{} {
				return make([]layers.DNSResourceRecord, 0, 4)
			},
		},
	}
}

func (p *MemoryPool) GetDNS() *layers.DNS {
	dns := p.dnsPool.Get().(*layers.DNS)
	dns.Questions = dns.Questions[:0]
	dns.Answers = dns.Answers[:0]
	dns.Authorities = nil
	dns.Additionals = nil
	dns.ID = 0
	dns.QR = false
	dns.OpCode = 0
	dns.AA = false
	dns.TC = false
	dns.RD = true
	dns.RA = false
	dns.Z = 0
	dns.ResponseCode = 0
	dns.QDCount = 0
	dns.ANCount = 0
	dns.NSCount = 0
	dns.ARCount = 0
	return dns
}

func (p *MemoryPool) PutDNS(dns *layers.DNS) {
	if dns != nil {
		p.dnsPool.Put(dns)
	}
}

func (p *MemoryPool) GetBuffer() gopacket.SerializeBuffer {
	buf := p.bufPool.Get().(gopacket.SerializeBuffer)
	buf.Clear()
	return buf
}

func (p *MemoryPool) PutBuffer(buf gopacket.SerializeBuffer) {
	if buf != nil {
		p.bufPool.Put(buf)
	}
}

func (p *MemoryPool) GetDNSQuestions() []layers.DNSQuestion {
	questions := p.questionPool.Get().([]layers.DNSQuestion)
	return questions[:0]
}

func (p *MemoryPool) PutDNSQuestions(questions []layers.DNSQuestion) {
	if questions != nil {
		p.questionPool.Put(questions)
	}
}

func (p *MemoryPool) GetDNSAnswers() []layers.DNSResourceRecord {
	answers := p.answerPool.Get().([]layers.DNSResourceRecord)
	return answers[:0]
}

func (p *MemoryPool) PutDNSAnswers(answers []layers.DNSResourceRecord) {
	if answers != nil {
		p.answerPool.Put(answers)
	}
}
