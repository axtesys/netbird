package types

const (
	// ClientHeader is the header used to identify the client
	ClientHeader = "x-nb-client"
	// ClientHeaderValue is the value of the ClientHeader
	ClientHeaderValue = "netbird"
	// GetURLPath is the path for the GetURL request
	GetURLPath = "/upload-url"

	// AXTESYS CHANGE: default debug-bundle upload server on axtesys infra.
	DefaultBundleURL = "https://upload.debug.netbird.axtesys.it" + GetURLPath
)

// GetURLResponse is the response for the GetURL request
type GetURLResponse struct {
	URL string
	Key string
}
