package auditcontent

import "testing"

func TestExtractRequestAcrossAPIs(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "Anthropic Messages keeps system and text blocks",
			body: `{"system":"be brief","messages":[{"role":"user","content":"hello"},` +
				`{"role":"assistant","content":[{"type":"text","text":"hi there"}]}]}`,
			want: "be brief\nhello\nhi there",
		},
		{
			name: "Chat Completions keeps each message",
			body: `{"messages":[{"role":"system","content":"rules"},` +
				`{"role":"user","content":"question"}]}`,
			want: "rules\nquestion",
		},
		{
			name: "Responses keeps instructions and input_text",
			body: `{"instructions":"be terse","input":[{"role":"user",` +
				`"content":[{"type":"input_text","text":"hi"}]}]}`,
			want: "be terse\nhi",
		},
		{
			name: "Gemini keeps systemInstruction and contents",
			body: `{"systemInstruction":{"parts":[{"text":"be nice"}]},` +
				`"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`,
			want: "be nice\nhello",
		},
		{
			name: "tool calls and results are left out",
			body: `{"messages":[{"role":"user","content":[{"type":"text","text":"run it"},` +
				`{"type":"tool_use","input":{"key":"secret"}},` +
				`{"type":"tool_result","content":"tool output"}]}]}`,
			want: "run it",
		},
		{
			name: "an unknown body is not sent",
			body: `{"foo":"bar"}`,
			want: "",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := ExtractRequest(test.body); got != test.want {
				t.Fatalf("ExtractRequest() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestExtractResponseAcrossAPIs(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "Anthropic content blocks",
			body: `{"content":[{"type":"thinking","thinking":"hidden"},` +
				`{"type":"text","text":"answer"}]}`,
			want: "answer",
		},
		{
			name: "Chat choices",
			body: `{"choices":[{"message":{"content":"chat answer"}}]}`,
			want: "chat answer",
		},
		{
			name: "Responses output",
			body: `{"output":[{"type":"message","content":` +
				`[{"type":"output_text","text":"out"}]}]}`,
			want: "out",
		},
		{
			name: "Gemini candidates",
			body: `{"candidates":[{"content":{"parts":[{"text":"gem"}]}}]}`,
			want: "gem",
		},
		{
			name: "Anthropic stream",
			body: "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
				"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n" +
				"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"lo\"}}\n\n" +
				"data: [DONE]\n",
			want: "Hello",
		},
		{
			name: "Chat stream",
			body: "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n" +
				"data: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n" +
				"data: [DONE]\n",
			want: "Hi there",
		},
		{
			name: "Responses stream",
			body: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Yo\"}\n\n" +
				"data: [DONE]\n",
			want: "Yo",
		},
		{
			name: "Gemini stream",
			body: "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"G\"}]}}]}\n\n" +
				"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"em\"}]}}]}\n\n",
			want: "Gem",
		},
		{
			name: "an unknown body is not sent",
			body: `{"error":{"message":"no"}}`,
			want: "",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := ExtractResponse(test.body); got != test.want {
				t.Fatalf("ExtractResponse() = %q, want %q", got, test.want)
			}
		})
	}
}
