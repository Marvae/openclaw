import Foundation

enum GatewayConnectionIssue: Equatable {
    case none
    case tokenMissing
    case unauthorized
    case pairingRequired(requestId: String?)
    case dnsResolution
    case tlsHandshake
    case timeout
    case network
    case unknown(String)

    var requestId: String? {
        if case let .pairingRequired(requestId) = self {
            return requestId
        }
        return nil
    }

    var needsAuthToken: Bool {
        switch self {
        case .tokenMissing, .unauthorized:
            return true
        default:
            return false
        }
    }

    var needsPairing: Bool {
        if case .pairingRequired = self { return true }
        return false
    }

    var userMessage: String {
        switch self {
        case .none:
            ""
        case .tokenMissing:
            "Gateway token is missing. Enter your auth token to continue."
        case .unauthorized:
            "Unauthorized. Check your token and password."
        case .pairingRequired:
            "Pairing required. Approve this device on the gateway host."
        case .dnsResolution:
            "Cannot resolve hostname. Check the address or your DNS settings."
        case .tlsHandshake:
            "TLS handshake failed. Check your TLS settings or try disabling TLS."
        case .timeout:
            "Connection timed out. The gateway may be unreachable."
        case .network:
            "Network error. Check that the gateway is running and reachable."
        case .unknown(let detail):
            detail
        }
    }

    static func detect(from statusText: String) -> Self {
        let trimmed = statusText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .none }
        let lower = trimmed.lowercased()

        if lower.contains("pairing required") || lower.contains("not_paired") || lower.contains("not paired") {
            return .pairingRequired(requestId: self.extractRequestId(from: trimmed))
        }
        if lower.contains("gateway token missing") {
            return .tokenMissing
        }
        if lower.contains("unauthorized") {
            return .unauthorized
        }
        if lower.contains("cannot find host") || lower.contains("name or service not known") ||
            lower.contains("nodename nor servname provided")
        {
            return .dnsResolution
        }
        if lower.contains("ssl") || lower.contains("certificate") || lower.contains("handshake") {
            return .tlsHandshake
        }
        if lower.contains("timed out") {
            return .timeout
        }
        if lower.contains("connection refused") ||
            lower.contains("network is unreachable") ||
            lower.contains("no route to host") ||
            lower.contains("could not connect")
        {
            return .network
        }
        if lower.hasPrefix("gateway error:") {
            return .unknown(trimmed)
        }
        return .none
    }

    private static func extractRequestId(from statusText: String) -> String? {
        let marker = "requestId:"
        guard let range = statusText.range(of: marker) else { return nil }
        let suffix = statusText[range.upperBound...]
        let trimmed = suffix.trimmingCharacters(in: .whitespacesAndNewlines)
        let end = trimmed.firstIndex(where: { ch in
            ch == ")" || ch.isWhitespace || ch == "," || ch == ";"
        }) ?? trimmed.endIndex
        let id = String(trimmed[..<end]).trimmingCharacters(in: .whitespacesAndNewlines)
        return id.isEmpty ? nil : id
    }
}
