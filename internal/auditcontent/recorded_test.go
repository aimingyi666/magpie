package auditcontent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The extraction is checked against traffic the gateway really recorded,
// kept in internal/gateway/testdata, rather than only against bodies made
// up for a test. Those files are another package's fixtures on purpose:
// there is one copy of the real bytes, and a move breaks this test loudly.
func recorded(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "gateway", "testdata", name))
	if err != nil {
		t.Fatalf("read recorded fixture %s: %v", name, err)
	}
	return string(data)
}

func TestExtractFromRecordedRequests(t *testing.T) {
	cases := []struct {
		file string
		want []string
		drop []string
	}{
		{
			// Claude Code, Anthropic Messages: a user turn and a system
			// turn whose blocks include a tool_addition that must stay out.
			file: "claude-code-advisor-turn.json",
			want: []string{"hi", "# Environment"},
			drop: []string{"tool_addition"},
		},
		{
			// Codex compaction, Responses input: a user turn and the
			// assistant turn it was compacted from.
			file: "codex-26.1007-compaction.json",
			want: []string{"对当前的接口做一次全测试", "我会先梳理项目里的接口"},
		},
		{
			// OpenCode, Chat Completions: a system prompt and the user turn.
			file: "opencode2_chat_tools.json",
			want: []string{"You are an AI agent running in OpenCode", "say hi"},
		},
		{
			// OpenCode, Responses: top-level instructions and the input.
			file: "opencode2_responses_tools.json",
			want: []string{"You are an AI agent running in OpenCode", "say hi"},
		},
	}
	for _, test := range cases {
		t.Run(test.file, func(t *testing.T) {
			got := ExtractRequest(recorded(t, test.file))
			if got == "" {
				t.Fatal("nothing extracted from a real request")
			}
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q in %q", want, got)
				}
			}
			for _, drop := range test.drop {
				if strings.Contains(got, drop) {
					t.Fatalf("kept %q, which is not conversation text", drop)
				}
			}
			if strings.Contains(got, `"type":`) {
				t.Fatalf("raw JSON leaked into the text: %q", got)
			}
		})
	}
}

func TestExtractFromRecordedStreams(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		// Anthropic Messages stream: one text delta.
		{file: "reasoning-uncounted-deepseek-anthropic.sse", want: []string{"391"}},
		// Chat Completions stream.
		{file: "vertex_openai_thoughts.sse", want: []string{"Acknowledging Greeting"}},
		// Responses stream: the answer before a tool call.
		{file: "grok_reasoning_then_call.sse", want: []string{"short, descriptive session title"}},
	}
	for _, test := range cases {
		t.Run(test.file, func(t *testing.T) {
			got := ExtractResponse(recorded(t, test.file))
			if got == "" {
				t.Fatal("nothing extracted from a real stream")
			}
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q in %q", want, got)
				}
			}
		})
	}
}

func TestAStreamWithNoTextSendsNothing(t *testing.T) {
	// A real Chat stream that carries role and provider chunks only: there
	// is no conversation text, so there is nothing to capture.
	if got := ExtractResponse(recorded(t, "clinepass_stream.sse")); got != "" {
		t.Fatalf("extracted %q from a stream with no text", got)
	}
}

// TestExtractFromLiveTraffic parses what one real call through a running
// magpie gateway recorded: a subscription answered "Hi" to "say hi in one
// word", once in Anthropic Messages and once in Responses (the gateway
// converted a Chat call upstream). The bytes are the gateway's own, not a
// hand-written sample.
func TestExtractFromLiveTraffic(t *testing.T) {
	cases := []struct{ request, response string }{
		{"anthropic-request.json", "anthropic-response.sse"},
		{"responses-request.json", "responses-response.sse"},
	}
	for _, test := range cases {
		t.Run(test.request, func(t *testing.T) {
			request, err := os.ReadFile(filepath.Join("testdata", "live", test.request))
			if err != nil {
				t.Fatal(err)
			}
			response, err := os.ReadFile(filepath.Join("testdata", "live", test.response))
			if err != nil {
				t.Fatal(err)
			}
			if got := ExtractRequest(string(request)); got != "say hi in one word" {
				t.Fatalf("prompt = %q", got)
			}
			if got := ExtractResponse(string(response)); got != "Hi" {
				t.Fatalf("reply = %q", got)
			}
		})
	}
}
