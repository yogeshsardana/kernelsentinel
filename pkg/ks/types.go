package ks

const (
	MaxPolicyName    = 256
	MaxPolicyRules   = 1024
	MaxProcessPath   = 4096
	HashSize         = 32
	PCRSelectionSize = 3
	MaxHSMTokens     = 16
	RingBufSize      = 1 << 20

	VersionMajor = 0
	VersionMinor = 1
	VersionPatch = 0
)

type EventType uint32

const (
	EventFileOpen     EventType = 0
	EventTaskAlloc    EventType = 1
	EventTaskFree     EventType = 2
	EventSocketBind   EventType = 3
	EventSocketConnect EventType = 4
	EventExecve       EventType = 5
	EventMMap         EventType = 6
	EventMProtect     EventType = 7
	EventBPFProgLoad  EventType = 8
	EventKernModuleLoad EventType = 9
	EventMax          EventType = 10
)

type Action uint32

const (
	ActionAllow     Action = 0
	ActionDeny      Action = 1
	ActionLog       Action = 2
	ActionReWait    Action = 3
	ActionTerminate Action = 4
)

type PolicyScope uint32

const (
	ScopeSystem    PolicyScope = 0
	ScopeProcess   PolicyScope = 1
	ScopeContainer PolicyScope = 2
	ScopeUser      PolicyScope = 3
)

type Attestation struct {
	Hash          [HashSize]byte
	PCRIndex      uint32
	PCRSelection  [PCRSelectionSize]byte
	ClockBootTime uint64
}

type PolicyHeader struct {
	Name              string
	Scope             PolicyScope
	RuleCount         uint32
	PolicyVersion     uint64
	Attestation       Attestation
	QuorumSignature   [256]byte
	QuorumSignatureLen uint32
	QuorumRequired    uint32
	QuorumTotal       uint32
}

type PolicyRule struct {
	Event       EventType `yaml:"event"`
	Action      Action    `yaml:"action"`
	ProcessPath string    `yaml:"process_path"`
	FlagsMask   uint64    `yaml:"flags_mask"`
	FlagsValue  uint64    `yaml:"flags_value"`
	UID         string    `yaml:"uid"`
	GID         string    `yaml:"gid"`
}

type Event struct {
	Sequence    uint64
	EventType   EventType
	PID         uint32
	TID         uint32
	UID         uint32
	GID         uint32
	TimestampNS uint64
	Retval      int64

	FileOpen struct {
		Inode    uint64
		DevMajor uint32
		DevMinor uint32
		Flags    uint32
	}

	TaskAlloc struct {
		ParentPID uint32
		ChildPID  uint32
	}

	SocketOp struct {
		Port   uint16
		Addr   uint32
		Domain int32
	}

	Execve struct {
		Filename [256]byte
		Argv     [1024]byte
	}

	MMap struct {
		Addr uint64
		Len  uint64
		Prot uint32
		Flags uint32
	}
}

type Stats struct {
	NumPolicies       uint32
	NumRulesTotal     uint32
	EventsProcessed   uint64
	EventsAllowed     uint64
	EventsDenied      uint64
	EventsLogged      uint64
	TPM2Queries       uint64
	HSMQuorumChecks   uint64
	RingBufOverruns   uint64
	UptimeNS          uint64
}
