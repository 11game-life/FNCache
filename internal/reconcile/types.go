package reconcile

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type ReconcileKind string

const (
	ReconcileGlobal         ReconcileKind = "Global"
	ReconcileLocalEndpoint  ReconcileKind = "LocalEndpoint"
	ReconcileRemoteEndpoint ReconcileKind = "RemoteEndpoint"
	ReconcileHealth         ReconcileKind = "Health"
)

type ReconcileKey struct {
	Kind      ReconcileKind
	Namespace string
	Name      string
	UID       string
	Reason    string
}

func (k ReconcileKey) QueueKey() string {
	return strings.Join([]string{string(k.Kind), k.Namespace, k.Name, k.UID}, "\x00")
}

type RemoteEndpoint struct {
	PodIPv4  netip.Addr
	NodeIPv4 netip.Addr
}

type DatapathSpec struct {
	ABI                uint32
	PinRoot            string
	Generation         uint64
	VXLANVNI           uint32
	VXLANUDPPort       uint16
	UnderlayIfIndex    int
	UnderlayIPv4       netip.Addr
	OverlayFingerprint string
}

type DesiredState struct {
	Generation      uint64
	Enabled         bool
	Capability      discovery.CapabilityReport
	LocalEndpoints  map[string]resolver.Endpoint
	RemoteEndpoints map[netip.Addr]RemoteEndpoint
	Datapath        DatapathSpec
}

type ActualState struct {
	ScannedAt   time.Time
	Control     ControlState
	Programs    map[string]ProgramState
	Maps        map[string]MapState
	Attachments []AttachmentState
	FlannelRule RuleState
	Orphans     []OwnedObject
	Conflicts   []discovery.Conflict
}

type OwnershipState struct {
	SchemaVersion   uint32                   `json:"schemaVersion"`
	InstallationID  string                   `json:"installationID"`
	NodeUID         string                   `json:"nodeUID"`
	Generation      uint64                   `json:"generation"`
	ELFBuildID      string                   `json:"elfBuildID"`
	ABI             uint32                   `json:"bpfABI"`
	Programs        map[string]ProgramState  `json:"programs"`
	Maps            map[string]MapState      `json:"maps"`
	Attachments     []AttachmentState        `json:"attachments"`
	Endpoints       map[string]OwnedEndpoint `json:"endpoints"`
	FlannelRule     OwnedRule                `json:"flannelRule"`
	LastCommittedAt time.Time                `json:"lastCommittedAt"`
}

type ControlState struct {
	Enabled        bool
	Generation     uint64
	HeartbeatAt    time.Time
	HeartbeatFresh bool
}

type ProgramState struct {
	ID   uint32
	Name string
	Tag  string
	ABI  uint32
}

type MapState struct {
	ID         uint32
	Name       string
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
}

type AttachmentState struct {
	Link      resolver.LinkIdentity
	Hook      string
	Program   string
	Priority  uint16
	Handle    uint32
	ProgramID uint32
}

type RuleState struct {
	Present     bool
	Identity    string
	Fingerprint string
}

type OwnedObject struct {
	Kind     string
	Identity string
}

type OwnedEndpoint struct {
	PodUID      string
	PodIPv4     netip.Addr
	NetNSInode  uint64
	PeerIfIndex int
	HostIfIndex int
}

type OwnedRule struct {
	Identity    string
	Comment     string
	Fingerprint string
}

type ErrorClass string

const (
	ErrorRetryable       ErrorClass = "Retryable"
	ErrorStale           ErrorClass = "Stale"
	ErrorUnsupported     ErrorClass = "Unsupported"
	ErrorConflict        ErrorClass = "OwnershipConflict"
	ErrorInvalidConfig   ErrorClass = "InvalidConfig"
	ErrorSafetyViolation ErrorClass = "SafetyViolation"
	ErrorInternal        ErrorClass = "Internal"
)

const (
	ReasonFlannelLinkMissing = "FLANNEL_LINK_MISSING"
	ReasonBPFABIMismatch     = "BPF_ABI_MISMATCH"
	ReasonTCForeignConflict  = "TC_FOREIGN_CONFLICT"
	ReasonEndpointNotReady   = "ENDPOINT_NOT_READY"
)

type ClassifiedError struct {
	class      ErrorClass
	reason     string
	retryAfter time.Duration
	cause      error
}

func NewClassifiedError(class ErrorClass, reason string, retryAfter time.Duration, cause error) *ClassifiedError {
	return &ClassifiedError{class: class, reason: reason, retryAfter: retryAfter, cause: cause}
}

func (e *ClassifiedError) Error() string {
	if e.cause == nil {
		return e.reason
	}
	return fmt.Sprintf("%s: %v", e.reason, e.cause)
}

func (e *ClassifiedError) Unwrap() error             { return e.cause }
func (e *ClassifiedError) Class() ErrorClass         { return e.class }
func (e *ClassifiedError) ReasonCode() string        { return e.reason }
func (e *ClassifiedError) RetryAfter() time.Duration { return e.retryAfter }
