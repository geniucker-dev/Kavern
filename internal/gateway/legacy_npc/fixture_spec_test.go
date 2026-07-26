package legacy_npc

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type gate6B1Fixture struct {
	Version           string                `json:"version"`
	Mode              string                `json:"mode"`
	BinarySHA256      map[string]string     `json:"binary_sha256"`
	Frames            []gate6B1Frame        `json:"frames"`
	ProbeSummary      []gate6B1Probe        `json:"probe_summary"`
	FieldMap          gate6B1FieldMap       `json:"field_map"`
	Readiness         string                `json:"readiness"`
	TargetTCPObserved bool                  `json:"target_tcp_observed"`
	EchoSuccess       bool                  `json:"echo_success"`
	SessionControl    gate6B1SessionControl `json:"session_control"`
	RedactionPolicy   []string              `json:"redaction_policy"`
}

type gate6B1SessionControl struct {
	Sequence                    []string `json:"sequence"`
	Client00BodyLen             int      `json:"client_00_body_len"`
	Server00BodyLen             int      `json:"server_00_body_len"`
	Server08BodyLen             int      `json:"server_08_body_len"`
	Client08BodyLen             int      `json:"client_08_body_len"`
	Server08EqualsClient00      bool     `json:"server_08_equals_client_00"`
	Client08EqualsServer00      bool     `json:"client_08_equals_server_00"`
	Server08EqualsServer00      bool     `json:"server_08_equals_server_00"`
	Client08EqualsClient00      bool     `json:"client_08_equals_client_00"`
	RelationshipConfirmed       bool     `json:"relationship_confirmed"`
	Complete                    bool     `json:"complete"`
	StrictDecoderRejectedStream bool     `json:"strict_decoder_rejected_stream"`
}

type gate6B1Frame struct {
	Version                       string   `json:"version"`
	Mode                          string   `json:"mode"`
	ConnectionRole                string   `json:"connection_role"`
	Direction                     string   `json:"direction"`
	Seq                           int      `json:"seq"`
	ProbeID                       int      `json:"probe_id"`
	PublicConnectionID            string   `json:"public_connection_id"`
	ByteCount                     int      `json:"byte_count"`
	SanitizedHex                  string   `json:"sanitized_hex"`
	CandidateOpcodeByte           string   `json:"candidate_opcode_byte"`
	CandidateStreamIDLE32         uint32   `json:"candidate_stream_id_le32"`
	CandidateLengthLE16           uint16   `json:"candidate_length_le16"`
	CandidateLengthLE32           uint32   `json:"candidate_length_le32"`
	CandidatePayloadOffset        int      `json:"candidate_payload_offset"`
	MetadataBodyFormat            string   `json:"metadata_body_format"`
	MetadataKeySummary            []string `json:"metadata_key_summary"`
	MetadataSanitizedPreview      string   `json:"metadata_sanitized_preview"`
	SemanticAddressPlaceholders   []string `json:"semantic_address_placeholders"`
	MetadataHostPlaceholder       string   `json:"metadata_host_placeholder"`
	MetadataRemoteAddrPlaceholder string   `json:"metadata_remote_addr_placeholder"`
	CloseCandidateDirection       string   `json:"close_candidate_direction"`
	CloseCandidateAfterEvent      string   `json:"close_candidate_after_event"`
	CloseCandidateStreamID        uint32   `json:"close_candidate_stream_id"`
	CloseSemanticsEvidence        string   `json:"close_semantics_evidence"`
	PayloadPlaceholder            string   `json:"payload_placeholder"`
	ObservedLabel                 string   `json:"observed_label"`
	TimingMarker                  string   `json:"timing_marker"`
	KnownFieldAnnotations         []string `json:"known_field_annotations"`
	UnknownFields                 []string `json:"unknown_fields"`
}

type gate6B1Probe struct {
	ProbeID            int    `json:"probe_id"`
	PublicConnectionID string `json:"public_connection_id"`
	PayloadLength      int    `json:"payload_length"`
	CloseObservation   string `json:"close_observation"`
}

type gate6B1FieldMap struct {
	FrameBoundaries             string   `json:"frame_boundaries"`
	FrameTypeFlagCandidates     []string `json:"frame_type_flag_candidates"`
	StreamCorrelationCandidates []string `json:"stream_correlation_id_candidates"`
	PayloadLengthCandidates     []string `json:"payload_length_candidates"`
	PayloadOffsetCandidates     []string `json:"payload_offset_candidates"`
	MetadataOpenStreamCandidate string   `json:"metadata_open_stream_candidate"`
	TCPPayloadFrameCandidate    string   `json:"tcp_payload_frame_candidate"`
	CloseResetEOFCandidate      string   `json:"close_reset_eof_candidate"`
	PingKeepaliveCandidate      string   `json:"ping_keepalive_candidate"`
	TargetSelectionSafety       string   `json:"target_selection_safety"`
	Unknowns                    []string `json:"unknowns"`
}

func TestGate6B1FixtureSchemaAndReadiness(t *testing.T) {
	fixture := readGate6B1Fixture(t)
	if fixture.Version != "gate6b1_fixture_v1" {
		t.Fatalf("fixture version = %q", fixture.Version)
	}
	if fixture.Mode != "stock_nps_oracle" {
		t.Fatalf("fixture mode = %q", fixture.Mode)
	}
	if fixture.Readiness != "insufficient for 6B-2" {
		t.Fatalf("fixture readiness = %q, want insufficient for 6B-2", fixture.Readiness)
	}
	if !fixture.TargetTCPObserved || !fixture.EchoSuccess {
		t.Fatalf("target_tcp_observed=%t echo_success=%t, want both true", fixture.TargetTCPObserved, fixture.EchoSuccess)
	}
	if fixture.BinarySHA256["npc"] == "" || fixture.BinarySHA256["nps"] == "" {
		t.Fatalf("fixture missing binary sha256 identifiers")
	}
	assertStableSessionControlRelationship(t, fixture.SessionControl)

	lengths := make([]int, 0, len(fixture.ProbeSummary))
	connections := map[string]struct{}{}
	for _, probe := range fixture.ProbeSummary {
		lengths = append(lengths, probe.PayloadLength)
		connections[probe.PublicConnectionID] = struct{}{}
		if !strings.Contains(probe.CloseObservation, "bounded chan grace") {
			t.Fatalf("probe %d close observation = %q", probe.ProbeID, probe.CloseObservation)
		}
	}
	sort.Ints(lengths)
	if !reflect.DeepEqual(lengths, []int{5, 19, 257}) {
		t.Fatalf("probe payload lengths = %v, want [5 19 257]", lengths)
	}
	if len(connections) < 2 {
		t.Fatalf("public connection count = %d, want at least 2", len(connections))
	}
	if len(fixture.Frames) == 0 {
		t.Fatal("fixture has no chan frames")
	}

	labels := map[string]bool{}
	largeMetadataFrames := 0
	splitMetadataHeaders := 0
	splitMetadataBodies := 0
	probePayloadLengths := map[int]int{}
	payloadLengthEvidence := map[int]bool{}
	splitPayloadLengthHeaders := map[int]int{}
	payloadOnlyEvidence := map[int]int{}
	metadataTargetEvidence := false
	closeCandidateProbes := map[int]bool{}
	for _, probe := range fixture.ProbeSummary {
		probePayloadLengths[probe.ProbeID] = probe.PayloadLength
	}
	for _, frame := range fixture.Frames {
		if frame.ConnectionRole != "legacy_nps_npc_chan" {
			t.Fatalf("frame %d role = %q", frame.Seq, frame.ConnectionRole)
		}
		if frame.Direction != "npc_to_nps" && frame.Direction != "nps_to_npc" {
			t.Fatalf("frame %d direction = %q", frame.Seq, frame.Direction)
		}
		if frame.Seq <= 0 || frame.ByteCount <= 0 || frame.SanitizedHex == "" || frame.ObservedLabel == "" || frame.TimingMarker == "" {
			t.Fatalf("frame has incomplete required fields: %+v", frame)
		}
		if len(frame.KnownFieldAnnotations) == 0 || len(frame.UnknownFields) == 0 {
			t.Fatalf("frame %d missing known/unknown annotations", frame.Seq)
		}
		if frame.CandidateOpcodeByte == "" && !strings.HasPrefix(frame.SanitizedHex, " <payload:") {
			t.Fatalf("frame %d missing candidate opcode byte", frame.Seq)
		}
		if frame.CandidateOpcodeByte == "0x03" && frame.CandidateLengthLE16 > 0 && int(frame.CandidateLengthLE16)+7 <= frame.ByteCount && frame.CandidatePayloadOffset == 0 {
			t.Fatalf("frame %d has 0x03 length candidate without payload/body offset", frame.Seq)
		}
		if frame.Direction == "nps_to_npc" && frame.MetadataBodyFormat != "" {
			largeMetadataFrames++
			switch frame.MetadataBodyFormat {
			case "json_object_generic":
				if frame.CandidateOpcodeByte != "0x03" || frame.CandidateLengthLE16 != 178 || frame.CandidateLengthLE32 != 174 || frame.CandidatePayloadOffset != 11 {
					t.Fatalf("complete metadata candidate frame %d has unexpected candidates: %+v", frame.Seq, frame)
				}
			case "split_continuation_json_object_generic":
				if frame.CandidateLengthLE32 != 174 || frame.CandidatePayloadOffset != 4 {
					t.Fatalf("split metadata candidate frame %d has unexpected candidates: %+v", frame.Seq, frame)
				}
			default:
				t.Fatalf("metadata candidate frame %d has unsupported format %q", frame.Seq, frame.MetadataBodyFormat)
			}
			if frame.MetadataSanitizedPreview == "" {
				t.Fatalf("metadata candidate frame %d missing sanitized preview", frame.Seq)
			}
			if strings.Contains(frame.MetadataSanitizedPreview, "<loopback>") {
				t.Fatalf("metadata candidate frame %d used generic loopback placeholder: %s", frame.Seq, frame.MetadataSanitizedPreview)
			}
			if frame.MetadataHostPlaceholder == "" || frame.MetadataRemoteAddrPlaceholder == "" {
				t.Fatalf("metadata candidate frame %d missing Host/RemoteAddr semantic placeholders: %+v", frame.Seq, frame)
			}
			for _, want := range []string{`"ConnType":"tcp"`, `"Compress":false`, `"Crypt":false`, `"LocalProxy":false`, `"ProtoVersion":""`, `"Timeout":5000000000`} {
				if !strings.Contains(frame.MetadataSanitizedPreview, want) {
					t.Fatalf("metadata candidate frame %d preview missing safe scalar %s: %s", frame.Seq, want, frame.MetadataSanitizedPreview)
				}
			}
			if containsString(frame.SemanticAddressPlaceholders, "<target_proxy_addr>") {
				metadataTargetEvidence = true
			}
		}
		if frame.Direction == "nps_to_npc" && frame.CandidateOpcodeByte == "0x03" && frame.CandidateLengthLE16 == 178 && frame.ByteCount < 185 {
			splitMetadataHeaders++
		}
		if frame.Direction == "nps_to_npc" && frame.ByteCount >= 178 && strings.HasPrefix(frame.SanitizedHex, "ae000000 <metadata_body:174>") {
			splitMetadataBodies++
		}
		if frame.PayloadPlaceholder != "" &&
			frame.MetadataBodyFormat == "" &&
			frame.CandidateOpcodeByte == "0x03" &&
			frame.CandidatePayloadOffset == 7 {
			payloadLengthEvidence[int(frame.CandidateLengthLE16)] = true
		}
		if frame.MetadataBodyFormat == "" &&
			frame.CandidateOpcodeByte == "0x03" &&
			frame.CandidatePayloadOffset == 0 &&
			frame.ByteCount == 7 &&
			frame.ProbeID > 0 &&
			int(frame.CandidateLengthLE16) == probePayloadLengths[frame.ProbeID] {
			splitPayloadLengthHeaders[frame.ProbeID] = int(frame.CandidateLengthLE16)
		}
		if frame.PayloadPlaceholder != "" &&
			frame.MetadataBodyFormat == "" &&
			frame.CandidateOpcodeByte == "" &&
			frame.ProbeID > 0 &&
			frame.ByteCount == probePayloadLengths[frame.ProbeID] {
			payloadOnlyEvidence[frame.ProbeID] = frame.ByteCount
		}
		if frame.CandidateOpcodeByte == "0x07" {
			if frame.CloseCandidateDirection == "" || frame.CloseCandidateStreamID == 0 || frame.CloseSemanticsEvidence == "" {
				t.Fatalf("close candidate frame %d missing close evidence fields: %+v", frame.Seq, frame)
			}
			if frame.CloseCandidateAfterEvent != "" {
				closeCandidateProbes[frame.ProbeID] = true
			}
		}
		labels[frame.ObservedLabel] = true
	}
	for _, want := range []string{"chan_possible_stream_open", "chan_possible_data_frame", "chan_possible_ping"} {
		if !labels[want] {
			t.Fatalf("fixture missing observed label %q", want)
		}
	}
	if len(fixture.FieldMap.Unknowns) == 0 {
		t.Fatal("fixture field map must keep unknowns explicit")
	}
	if largeMetadataFrames+minInt(splitMetadataHeaders, splitMetadataBodies) < 3 {
		t.Fatalf("metadata candidate evidence complete=%d split_headers=%d split_bodies=%d, want at least 3 total candidates", largeMetadataFrames, splitMetadataHeaders, splitMetadataBodies)
	}
	for _, want := range []int{5, 19, 257} {
		if !payloadLengthEvidence[want] && !hasSplitPayloadEvidence(want, splitPayloadLengthHeaders, payloadOnlyEvidence) {
			t.Fatalf("missing payload length evidence for %d bytes", want)
		}
	}
	if !metadataTargetEvidence {
		t.Fatal("metadata fixture lacks target_proxy_addr semantic placeholder evidence")
	}
	if fixture.Readiness == "sufficient for 6B-2 plan" && len(closeCandidateProbes) < 2 {
		t.Fatalf("readiness is sufficient but close candidate probes = %d, want at least 2", len(closeCandidateProbes))
	}
	if !strings.Contains(fixture.FieldMap.TCPPayloadFrameCandidate, "0x03") ||
		!strings.Contains(fixture.FieldMap.TCPPayloadFrameCandidate, "5 / 19 / 257") {
		t.Fatalf("tcp payload field map does not cite 0x03 and probe evidence: %q", fixture.FieldMap.TCPPayloadFrameCandidate)
	}
	if !strings.Contains(fixture.FieldMap.TargetSelectionSafety, "<target_proxy_addr>") {
		t.Fatalf("target safety field map does not cite target proxy placeholder: %q", fixture.FieldMap.TargetSelectionSafety)
	}
}

func hasSplitPayloadEvidence(want int, headers, payloads map[int]int) bool {
	for probeID, headerLen := range headers {
		if headerLen == want && payloads[probeID] == want {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestGate6B1FixtureRedaction(t *testing.T) {
	data := readGate6B1FixtureBytes(t)
	for _, forbidden := range []string{
		"abcde",
		"kavern-observe-echo",
		"zzzz",
		"127.0.0.1",
		"-server=",
		"vkey:",
		"auth_key=",
		"web_password=",
		"6162636465",
		"6b617665726e2d6f6273657276652d6563686f",
		"7a7a7a7a7a",
		"redacted_body",
		"32303236",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("fixture contains forbidden raw material %q", forbidden)
		}
	}
}

func assertStableSessionControlRelationship(t *testing.T, evidence gate6B1SessionControl) {
	t.Helper()
	if len(evidence.Sequence) != 4 {
		t.Fatalf("session control sequence length = %d, want 4", len(evidence.Sequence))
	}
	if !evidence.Complete || evidence.StrictDecoderRejectedStream || !evidence.RelationshipConfirmed {
		t.Fatalf("session control evidence complete=%t rejected=%t confirmed=%t", evidence.Complete, evidence.StrictDecoderRejectedStream, evidence.RelationshipConfirmed)
	}
	if evidence.Client00BodyLen <= 0 || evidence.Server00BodyLen <= 0 || evidence.Server08BodyLen <= 0 || evidence.Client08BodyLen <= 0 {
		t.Fatalf("session control body lengths = client00=%d server00=%d server08=%d client08=%d", evidence.Client00BodyLen, evidence.Server00BodyLen, evidence.Server08BodyLen, evidence.Client08BodyLen)
	}
	if !evidence.Server08EqualsClient00 || !evidence.Client08EqualsServer00 {
		t.Fatalf("session control acknowledgement mapping = server08/client00=%t client08/server00=%t", evidence.Server08EqualsClient00, evidence.Client08EqualsServer00)
	}
	if evidence.Server08EqualsServer00 || evidence.Client08EqualsClient00 {
		t.Fatalf("session control body pairs unexpectedly equal: server08/server00=%t client08/client00=%t", evidence.Server08EqualsServer00, evidence.Client08EqualsClient00)
	}
}

func TestGate6B1CandidateLogicalFrameSplitter(t *testing.T) {
	fixture := readGate6B1Fixture(t)
	probeLengths := map[uint32]int{}
	for _, probe := range fixture.ProbeSummary {
		probeLengths[uint32(probe.ProbeID)] = probe.PayloadLength
	}

	allFrames := make([]candidateLogicalFrame, 0)
	for _, direction := range []string{"nps_to_npc", "npc_to_nps"} {
		stream, err := fixtureTokenStream(fixture.Frames, direction)
		if err != nil {
			t.Fatalf("build sanitized token stream direction=%s: %v", direction, err)
		}
		frames, err := splitCandidateLogicalFrames(direction, stream)
		if err != nil {
			t.Fatalf("split candidate logical frames direction=%s: %v", direction, err)
		}
		if len(frames) == 0 {
			t.Fatalf("direction=%s produced no logical frames", direction)
		}
		allFrames = append(allFrames, frames...)
		assertSessionControlSeparated(t, direction, frames)
	}

	streamSeen := map[uint32]bool{}
	for _, frame := range allFrames {
		if frame.StreamID >= 1 && frame.StreamID <= 3 {
			streamSeen[frame.StreamID] = true
		}
	}
	for _, streamID := range []uint32{1, 2, 3} {
		if !streamSeen[streamID] {
			t.Fatalf("stream id %d was not found in candidate logical frames", streamID)
		}
		assertProbeLogicalFrames(t, allFrames, streamID, probeLengths[streamID])
	}
}

func assertSessionControlSeparated(t *testing.T, direction string, frames []candidateLogicalFrame) {
	t.Helper()
	for _, frame := range frames {
		if (frame.Opcode == 0x00 || frame.Opcode == 0x08) && frame.Kind != "session_control" {
			t.Fatalf("direction=%s opcode=0x%02x classified as %q, want session_control", direction, frame.Opcode, frame.Kind)
		}
		if frame.Kind == "session_control" && frame.StreamID != 0xffffffff {
			t.Fatalf("direction=%s session/control stream id = %d, want 0xffffffff", direction, frame.StreamID)
		}
	}
}

func assertProbeLogicalFrames(t *testing.T, frames []candidateLogicalFrame, streamID uint32, payloadLen int) {
	t.Helper()
	hasOpen := false
	hasMetadata := false
	hasNpsPayload := false
	hasNPCPayload := false
	closeDirections := map[string]bool{}
	for _, frame := range frames {
		if frame.StreamID != streamID {
			continue
		}
		switch frame.Kind {
		case "short_stream_control":
			if frame.Opcode == 0x01 || frame.Opcode == 0x06 {
				hasOpen = true
			}
			if frame.Opcode == 0x07 {
				closeDirections[frame.Direction] = true
			}
		case "data_metadata":
			if frame.Direction == "nps_to_npc" && frame.BodyLen == 178 && frame.MetadataLen == 174 {
				hasMetadata = true
			}
		case "data_payload":
			if frame.BodyLen == payloadLen {
				if frame.Direction == "nps_to_npc" {
					hasNpsPayload = true
				}
				if frame.Direction == "npc_to_nps" {
					hasNPCPayload = true
				}
			}
		}
	}
	if !hasOpen {
		t.Fatalf("stream %d missing open/control candidate", streamID)
	}
	if !hasMetadata {
		t.Fatalf("stream %d missing nps_to_npc metadata candidate", streamID)
	}
	if !hasNpsPayload {
		t.Fatalf("stream %d missing nps_to_npc payload candidate length=%d", streamID, payloadLen)
	}
	if !hasNPCPayload {
		t.Fatalf("stream %d missing npc_to_nps payload candidate length=%d", streamID, payloadLen)
	}
	if !closeDirections["nps_to_npc"] || !closeDirections["npc_to_nps"] {
		t.Fatalf("stream %d close candidate directions = %v, want both directions", streamID, closeDirections)
	}
}

type fixtureToken struct {
	Value       byte
	Known       bool
	Placeholder string
}

type candidateLogicalFrame struct {
	Direction   string
	Kind        string
	Opcode      byte
	StreamID    uint32
	BodyLen     int
	MetadataLen int
	Start       int
	Length      int
}

func fixtureTokenStream(frames []gate6B1Frame, direction string) ([]fixtureToken, error) {
	var stream []fixtureToken
	for _, frame := range frames {
		if frame.Direction != direction {
			continue
		}
		tokens, err := parseSanitizedFixtureHex(frame.SanitizedHex)
		if err != nil {
			return nil, fmt.Errorf("seq=%d: %w", frame.Seq, err)
		}
		if len(tokens) != frame.ByteCount {
			return nil, fmt.Errorf("seq=%d token length=%d byte_count=%d", frame.Seq, len(tokens), frame.ByteCount)
		}
		stream = append(stream, tokens...)
	}
	return stream, nil
}

func parseSanitizedFixtureHex(text string) ([]fixtureToken, error) {
	var out []fixtureToken
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "<") {
			n, err := placeholderLength(part)
			if err != nil {
				return nil, err
			}
			for i := 0; i < n; i++ {
				out = append(out, fixtureToken{Placeholder: part})
			}
			continue
		}
		if len(part)%2 != 0 {
			return nil, fmt.Errorf("hex segment has odd length")
		}
		raw, err := hex.DecodeString(part)
		if err != nil {
			return nil, err
		}
		for _, b := range raw {
			out = append(out, fixtureToken{Value: b, Known: true})
		}
	}
	return out, nil
}

func placeholderLength(part string) (int, error) {
	part = strings.TrimPrefix(strings.TrimSuffix(part, ">"), "<")
	idx := strings.LastIndex(part, ":")
	if idx < 0 {
		return 0, fmt.Errorf("placeholder %q missing length", part)
	}
	n, err := strconv.Atoi(part[idx+1:])
	if err != nil {
		return 0, fmt.Errorf("placeholder %q invalid length: %w", part, err)
	}
	return n, nil
}

func splitCandidateLogicalFrames(direction string, stream []fixtureToken) ([]candidateLogicalFrame, error) {
	var frames []candidateLogicalFrame
	for off := 0; off < len(stream); {
		opcode, ok := knownByte(stream, off)
		if !ok {
			return nil, fmt.Errorf("offset=%d starts with placeholder byte", off)
		}
		switch opcode {
		case 0x01, 0x06, 0x07:
			frame, err := splitFixedStreamControl(direction, stream, off, 5, "short_stream_control")
			if err != nil {
				return nil, err
			}
			frames = append(frames, frame)
			off += frame.Length
		case 0x05:
			frame, err := splitFixedStreamControl(direction, stream, off, 13, "window_control")
			if err != nil {
				return nil, err
			}
			frames = append(frames, frame)
			off += frame.Length
		case 0x00, 0x08:
			frame, err := splitSessionControl(direction, stream, off)
			if err != nil {
				return nil, err
			}
			frames = append(frames, frame)
			off += frame.Length
		case 0x03:
			frame, err := splitDataFrame(direction, stream, off)
			if err != nil {
				return nil, err
			}
			frames = append(frames, frame)
			off += frame.Length
		default:
			return nil, fmt.Errorf("offset=%d unsupported candidate opcode=0x%02x", off, opcode)
		}
	}
	return frames, nil
}

func splitFixedStreamControl(direction string, stream []fixtureToken, off, n int, kind string) (candidateLogicalFrame, error) {
	if off+n > len(stream) {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d short %s frame truncated", off, kind)
	}
	streamID, ok := knownLE32(stream, off+1)
	if !ok {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d %s stream id not known", off, kind)
	}
	opcode, _ := knownByte(stream, off)
	return candidateLogicalFrame{Direction: direction, Kind: kind, Opcode: opcode, StreamID: streamID, Start: off, Length: n}, nil
}

func splitSessionControl(direction string, stream []fixtureToken, off int) (candidateLogicalFrame, error) {
	if off+7 > len(stream) {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d session/control header truncated", off)
	}
	streamID, ok := knownLE32(stream, off+1)
	if !ok {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d session/control stream id not known", off)
	}
	bodyLen, ok := knownLE16(stream, off+5)
	if !ok {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d session/control length not known", off)
	}
	total := 7 + int(bodyLen)
	if off+total > len(stream) {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d session/control length=%d exceeds stream", off, bodyLen)
	}
	opcode, _ := knownByte(stream, off)
	return candidateLogicalFrame{Direction: direction, Kind: "session_control", Opcode: opcode, StreamID: streamID, BodyLen: int(bodyLen), Start: off, Length: total}, nil
}

func splitDataFrame(direction string, stream []fixtureToken, off int) (candidateLogicalFrame, error) {
	if off+7 > len(stream) {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d data header truncated", off)
	}
	streamID, ok := knownLE32(stream, off+1)
	if !ok {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d data stream id not known", off)
	}
	bodyLen, ok := knownLE16(stream, off+5)
	if !ok {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d data length not known", off)
	}
	total := 7 + int(bodyLen)
	if off+total > len(stream) {
		return candidateLogicalFrame{}, fmt.Errorf("offset=%d data length=%d exceeds stream", off, bodyLen)
	}
	kind := "data_payload"
	metadataLen := 0
	if bodyLen >= 4 {
		if len32, ok := knownLE32(stream, off+7); ok && int(len32) == int(bodyLen)-4 {
			kind = "data_metadata"
			metadataLen = int(len32)
		}
	}
	return candidateLogicalFrame{Direction: direction, Kind: kind, Opcode: 0x03, StreamID: streamID, BodyLen: int(bodyLen), MetadataLen: metadataLen, Start: off, Length: total}, nil
}

func knownByte(stream []fixtureToken, off int) (byte, bool) {
	if off < 0 || off >= len(stream) || !stream[off].Known {
		return 0, false
	}
	return stream[off].Value, true
}

func knownLE16(stream []fixtureToken, off int) (uint16, bool) {
	if off+2 > len(stream) {
		return 0, false
	}
	var raw [2]byte
	for i := range raw {
		b, ok := knownByte(stream, off+i)
		if !ok {
			return 0, false
		}
		raw[i] = b
	}
	return binary.LittleEndian.Uint16(raw[:]), true
}

func knownLE32(stream []fixtureToken, off int) (uint32, bool) {
	if off+4 > len(stream) {
		return 0, false
	}
	var raw [4]byte
	for i := range raw {
		b, ok := knownByte(stream, off+i)
		if !ok {
			return 0, false
		}
		raw[i] = b
	}
	return binary.LittleEndian.Uint32(raw[:]), true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func readGate6B1Fixture(t *testing.T) gate6B1Fixture {
	t.Helper()
	data := readGate6B1FixtureBytes(t)
	var fixture gate6B1Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode Gate 6B-1 fixture: %v", err)
	}
	return fixture
}

func readGate6B1FixtureBytes(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "legacy_npc", "testdata", "stock_nps_v0.26.34", "tcp_echo_chan_frames.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Gate 6B-1 fixture: %v", err)
	}
	return data
}
