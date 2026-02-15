import Testing
@testable import OpenClaw

@Suite(.serialized) struct GatewayConnectionIssueTests {
    @Test func detectsTokenMissing() {
        let issue = GatewayConnectionIssue.detect(from: "unauthorized: gateway token missing")
        #expect(issue == .tokenMissing)
        #expect(issue.needsAuthToken)
    }

    @Test func detectsUnauthorized() {
        let issue = GatewayConnectionIssue.detect(from: "Gateway error: unauthorized role")
        #expect(issue == .unauthorized)
        #expect(issue.needsAuthToken)
    }

    @Test func detectsPairingWithRequestId() {
        let issue = GatewayConnectionIssue.detect(from: "pairing required (requestId: abc123)")
        #expect(issue == .pairingRequired(requestId: "abc123"))
        #expect(issue.needsPairing)
        #expect(issue.requestId == "abc123")
    }

    @Test func detectsDnsResolution() {
        let issue = GatewayConnectionIssue.detect(from: "Error: cannot find host")
        #expect(issue == .dnsResolution)
    }

    @Test func detectsTlsHandshake() {
        let issue = GatewayConnectionIssue.detect(from: "SSL handshake failed")
        #expect(issue == .tlsHandshake)
    }

    @Test func detectsTimeout() {
        let issue = GatewayConnectionIssue.detect(from: "Gateway error: timed out")
        #expect(issue == .timeout)
    }

    @Test func detectsNetworkError() {
        let issue = GatewayConnectionIssue.detect(from: "Gateway error: Connection refused")
        #expect(issue == .network)
    }

    @Test func detectsNoRouteToHost() {
        let issue = GatewayConnectionIssue.detect(from: "No route to host")
        #expect(issue == .network)
    }

    @Test func returnsNoneForBenignStatus() {
        let issue = GatewayConnectionIssue.detect(from: "Connected")
        #expect(issue == .none)
    }

    @Test func userMessageIsNotEmpty() {
        let cases: [GatewayConnectionIssue] = [
            .tokenMissing, .unauthorized, .dnsResolution,
            .tlsHandshake, .timeout, .network, .unknown("oops"),
        ]
        for issue in cases {
            #expect(!issue.userMessage.isEmpty)
        }
    }
}
