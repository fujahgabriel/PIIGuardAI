import Foundation

/// A hostname (or suffix) belonging to a known LLM provider that should be
/// routed through the local MITM proxy for inspection.
struct ProviderDomain: Identifiable, Hashable, Codable {
    var id: String { host }
    var host: String
    var providerName: String
    var isEnabled: Bool = true
    /// True for domains the user added themselves (deletable). Built-in
    /// defaults from `DefaultProviders.all` can only be disabled, never
    /// deleted, so re-enabling one never requires re-typing it.
    var isCustom: Bool = false

    /// Whether `candidateHost` matches this entry (exact match or subdomain).
    func matches(_ candidateHost: String) -> Bool {
        let candidate = candidateHost.lowercased()
        let target = host.lowercased()
        return candidate == target || candidate.hasSuffix("." + target)
    }
}

enum DefaultProviders {
    static let all: [ProviderDomain] = [
        ProviderDomain(host: "claude.ai", providerName: "Claude"),
        ProviderDomain(host: "api.anthropic.com", providerName: "Anthropic API"),
        ProviderDomain(host: "chatgpt.com", providerName: "ChatGPT"),
        ProviderDomain(host: "chat.openai.com", providerName: "ChatGPT"),
        ProviderDomain(host: "api.openai.com", providerName: "OpenAI API"),
        ProviderDomain(host: "gemini.google.com", providerName: "Gemini"),
        ProviderDomain(host: "generativelanguage.googleapis.com", providerName: "Google AI API"),
        ProviderDomain(host: "api.cohere.ai", providerName: "Cohere API"),
        ProviderDomain(host: "api.mistral.ai", providerName: "Mistral API"),
        ProviderDomain(host: "api.x.ai", providerName: "xAI API"),
        ProviderDomain(host: "grok.com", providerName: "Grok"),
        ProviderDomain(host: "perplexity.ai", providerName: "Perplexity"),
        ProviderDomain(host: "api.perplexity.ai", providerName: "Perplexity API"),
        ProviderDomain(host: "opencode.ai", providerName: "opencode"),
        ProviderDomain(host: "models.opencode.ai", providerName: "opencode"),
        ProviderDomain(host: "openrouter.ai", providerName: "OpenRouter"),
    ]
}
