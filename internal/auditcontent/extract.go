package auditcontent

import (
	"encoding/json"
	"strings"
)

// ExtractRequest is the conversation text an agent asked with: the system
// prompt and each message's text, across the four APIs the gateway speaks
// (Anthropic Messages, OpenAI Responses, Chat Completions, Gemini). Tool
// definitions, tool arguments, images and every other field stay out: the
// audit stream records what was said, not the machinery around it.
//
// A body it does not recognize answers "" so the caller sends nothing,
// rather than sending raw JSON that happens to be text.
func ExtractRequest(body string) string {
	object := parseObject(body)
	if object == nil {
		return ""
	}
	var parts []string
	parts = addText(parts, object["system"])
	parts = addText(parts, object["instructions"])
	if system, ok := object["systemInstruction"].(map[string]any); ok {
		parts = addGeminiParts(parts, system["parts"])
	}
	if contents, ok := object["contents"].([]any); ok {
		for _, item := range contents {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			parts = addGeminiParts(parts, entry["parts"])
		}
	}
	if input := object["input"]; input != nil {
		parts = addResponsesInput(parts, input)
	}
	if messages, ok := object["messages"].([]any); ok {
		parts = addMessages(parts, messages)
	}
	return joinParts(parts)
}

// ExtractResponse is the text the vendor answered with, from a JSON reply
// or from a stream of server-sent events.
func ExtractResponse(body string) string {
	if isEventStream(body) {
		return extractStream(body)
	}
	object := parseObject(body)
	if object == nil {
		return ""
	}
	var parts []string
	if blocks, ok := object["content"].([]any); ok {
		parts = addContentBlocks(parts, blocks)
	}
	if choices, ok := object["choices"].([]any); ok {
		for _, item := range choices {
			choice, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if message, ok := choice["message"].(map[string]any); ok {
				parts = addText(parts, message["content"])
			}
		}
	}
	if output, ok := object["output"].([]any); ok {
		for _, item := range output {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if content, ok := entry["content"].([]any); ok {
				parts = addContentBlocks(parts, content)
			}
		}
	}
	if candidates, ok := object["candidates"].([]any); ok {
		for _, item := range candidates {
			candidate, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if content, ok := candidate["content"].(map[string]any); ok {
				parts = addGeminiParts(parts, content["parts"])
			}
		}
	}
	return joinParts(parts)
}

func parseObject(body string) map[string]any {
	text := strings.TrimSpace(body)
	if text == "" || !strings.HasPrefix(text, "{") {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil
	}
	return object
}

func isEventStream(body string) bool {
	text := strings.TrimSpace(body)
	if strings.HasPrefix(text, "data:") || strings.HasPrefix(text, "event:") {
		return true
	}
	return strings.Contains(text, "\ndata:") || strings.Contains(text, "\nevent:")
}

// extractStream reads the text deltas of a streamed reply: Anthropic's
// content_block_delta, Chat's choices[].delta.content, Responses'
// response.output_text.delta and Gemini's candidates[].content.parts[].text.
func extractStream(body string) string {
	var parts []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		object := parseObject(payload)
		if object == nil {
			continue
		}
		event, _ := object["type"].(string)
		switch event {
		case "content_block_delta":
			if delta, ok := object["delta"].(map[string]any); ok {
				parts = addText(parts, delta["text"])
			}
			continue
		case "response.output_text.delta":
			parts = addText(parts, object["delta"])
			continue
		}
		if choices, ok := object["choices"].([]any); ok {
			for _, item := range choices {
				choice, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if delta, ok := choice["delta"].(map[string]any); ok {
					parts = addText(parts, delta["content"])
				}
			}
		}
		if candidates, ok := object["candidates"].([]any); ok {
			for _, item := range candidates {
				candidate, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if content, ok := candidate["content"].(map[string]any); ok {
					parts = addGeminiParts(parts, content["parts"])
				}
			}
		}
	}
	// A stream's deltas are the pieces of one answer: they join with
	// nothing between them, unlike separate blocks.
	return strings.TrimSpace(strings.Join(parts, ""))
}

// addText keeps a string, an array of content blocks, or a single block.
func addText(parts []string, value any) []string {
	switch typed := value.(type) {
	case string:
		return appendNonEmpty(parts, typed)
	case []any:
		return addContentBlocks(parts, typed)
	case map[string]any:
		return addContentBlock(parts, typed)
	}
	return parts
}

// addContentBlocks keeps the text of Anthropic, Chat and Responses blocks;
// tool_use, tool_result, image and other blocks are left out.
func addContentBlocks(parts []string, blocks []any) []string {
	for _, item := range blocks {
		if block, ok := item.(map[string]any); ok {
			parts = addContentBlock(parts, block)
		}
	}
	return parts
}

func addContentBlock(parts []string, block map[string]any) []string {
	kind, _ := block["type"].(string)
	if kind != "" && kind != "text" && kind != "input_text" && kind != "output_text" {
		return parts
	}
	return addText(parts, block["text"])
}

// addMessages keeps each message's text in order, across Anthropic's and
// Chat's message lists (their content blocks are the same shape).
func addMessages(parts []string, messages []any) []string {
	for _, item := range messages {
		message, ok := item.(map[string]any)
		if !ok {
			continue
		}
		parts = addText(parts, message["content"])
	}
	return parts
}

// addResponsesInput covers the Responses API's input: a string, or items
// whose content is a string or a list of input_text blocks.
func addResponsesInput(parts []string, input any) []string {
	switch typed := input.(type) {
	case string:
		return appendNonEmpty(parts, typed)
	case []any:
		for _, item := range typed {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			parts = addText(parts, entry["content"])
		}
	case map[string]any:
		parts = addText(parts, typed["content"])
	}
	return parts
}

func addGeminiParts(parts []string, value any) []string {
	items, ok := value.([]any)
	if !ok {
		return parts
	}
	for _, item := range items {
		part, ok := item.(map[string]any)
		if !ok {
			continue
		}
		parts = appendNonEmpty(parts, part["text"])
	}
	return parts
}

func appendNonEmpty(parts []string, value any) []string {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return parts
	}
	return append(parts, text)
}

func joinParts(parts []string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, "\n")
}
