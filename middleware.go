package pact

import (
	"context"
	"net/http"
)

// pactContextKey is the context key for storing Pact verification results.
type pactContextKey struct{}

// MiddlewareConfig configures the Pact verification middleware.
type MiddlewareConfig struct {
	// VerifyOptions controls how delegation chains and requests are verified.
	VerifyOptions VerifyOptions

	// OnVerified is called after successful verification.
	// Use this for logging, metrics, or custom authorization logic.
	// If nil, verification result is silently added to context.
	OnVerified func(r *http.Request, result *VerificationResult)

	// OnFailed is called when verification fails.
	// If nil, the middleware returns 401 with the error message.
	// Return true to continue to the next handler anyway (permissive mode).
	OnFailed func(w http.ResponseWriter, r *http.Request, result *VerificationResult) bool

	// Optional controls whether Pact authentication is required.
	// If true, requests without Pact headers pass through to the next handler
	// with no VerificationResult in context (the handler can check with FromContext).
	// If false (default), requests without Pact headers are rejected with 401.
	Optional bool

	// CapabilityForRequest dynamically determines the required capability for a request.
	// This is called per-request and overrides VerifyOptions.RequiredCapability.
	// If nil, VerifyOptions.RequiredCapability is used for all requests.
	//
	// Example:
	//   func(r *http.Request) string {
	//       if r.Method == "GET" { return "api:read" }
	//       return "api:write"
	//   }
	CapabilityForRequest func(r *http.Request) string
}

// Middleware returns an http.Handler middleware that verifies Pact-signed requests.
//
// This is the primary integration point for providers. Add it to your HTTP server
// to verify agent delegation chains and request signatures on every request.
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/api/data", handleData)
//
//	protected := pact.Middleware(pact.MiddlewareConfig{
//	    VerifyOptions: pact.VerifyOptions{
//	        RequiredCapability: "api:read",
//	    },
//	})(mux)
//
//	http.ListenAndServe(":8080", protected)
//
// After verification, use pact.FromContext(r.Context()) in your handler to access
// the verified agent identity, root authority, and capabilities.
func Middleware(config MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the request has Pact headers
			if !hasPactHeaders(r) {
				if config.Optional {
					// No Pact headers, but auth is optional — pass through
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "pact: missing authentication headers", http.StatusUnauthorized)
				return
			}

			// Determine required capability for this request
			opts := config.VerifyOptions
			if config.CapabilityForRequest != nil {
				opts.RequiredCapability = config.CapabilityForRequest(r)
			}

			// Verify the request
			result := VerifyRequest(r, opts)

			if !result.Valid {
				if config.OnFailed != nil {
					if config.OnFailed(w, r, result) {
						// OnFailed returned true — continue anyway
						ctx := context.WithValue(r.Context(), pactContextKey{}, result)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					return // OnFailed handled the response
				}
				http.Error(w, "pact: "+result.Error, http.StatusUnauthorized)
				return
			}

			// Verification succeeded
			if config.OnVerified != nil {
				config.OnVerified(r, result)
			}

			// Attach result to context and continue
			ctx := context.WithValue(r.Context(), pactContextKey{}, result)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireCapability returns a middleware that checks for a specific capability.
// This is a convenience wrapper for per-route capability requirements.
//
// Usage:
//
//	mux.Handle("/deploy", pact.RequireCapability("deploy:create")(handleDeploy))
func RequireCapability(capability string) func(http.Handler) http.Handler {
	return Middleware(MiddlewareConfig{
		VerifyOptions: VerifyOptions{
			RequiredCapability: capability,
		},
	})
}

// FromContext extracts the Pact verification result from the request context.
// Returns nil if the request was not verified (e.g., Optional mode with no headers).
//
// Usage:
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    result := pact.FromContext(r.Context())
//	    if result == nil {
//	        // No Pact auth on this request (Optional mode)
//	        return
//	    }
//	    fmt.Println("Agent:", result.AgentID)
//	    fmt.Println("Root:", result.RootAuthority)
//	}
func FromContext(ctx context.Context) *VerificationResult {
	result, _ := ctx.Value(pactContextKey{}).(*VerificationResult)
	return result
}

// MustFromContext extracts the Pact verification result from the request context.
// Panics if no result is present (use only behind non-optional middleware).
func MustFromContext(ctx context.Context) *VerificationResult {
	result := FromContext(ctx)
	if result == nil {
		panic("pact: MustFromContext called without Pact middleware or in Optional mode with no headers")
	}
	return result
}

// hasPactHeaders checks if the request contains Pact authentication headers.
func hasPactHeaders(r *http.Request) bool {
	return r.Header.Get(HeaderAgentIdentity) != "" && r.Header.Get(HeaderDelegationChain) != ""
}
