package winapi

import (
	"errors"
	"fmt"
	"syscall"
)

const eventLogErrorNoMoreItems syscall.Errno = 259

// classifyEventLogNextResult treats ERROR_NO_MORE_ITEMS as the normal end of
// an Event Log query while keeping other EvtNext failures visible to callers.
func classifyEventLogNextResult(result uintptr, callErr error) (done bool, err error) {
	if result != 0 {
		return false, nil
	}
	if errors.Is(callErr, eventLogErrorNoMoreItems) {
		return true, nil
	}
	if callErr == nil {
		return false, errors.New("EvtNext failed without an error code")
	}
	return false, fmt.Errorf("EvtNext failed: %w", callErr)
}
