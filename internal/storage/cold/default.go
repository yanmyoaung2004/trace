package cold

// defaultReaderName is set at init time based on build tags (cgo vs pure).
var defaultReaderName = "parquet-go (pure Go)"

// DefaultReaderName returns the name of the default cold reader implementation.
func DefaultReaderName() string {
	return defaultReaderName
}
