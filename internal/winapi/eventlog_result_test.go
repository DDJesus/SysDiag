package winapi

import (
	"errors"
	"syscall"
	"testing"
)

func TestClassifyEventLogNextResult(t *testing.T) {
	tests := []struct {
		name     string
		result   uintptr
		callErr  error
		wantDone bool
		wantErr  bool
	}{
		{name: "event returned", result: 1},
		{name: "normal end", callErr: eventLogErrorNoMoreItems, wantDone: true},
		{name: "real failure", callErr: syscall.Errno(5), wantErr: true},
		{name: "missing failure code", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done, err := classifyEventLogNextResult(tt.result, tt.callErr)
			if done != tt.wantDone || (err != nil) != tt.wantErr {
				t.Fatalf("classifyEventLogNextResult() = (%v, %v), want done=%v err=%v", done, err, tt.wantDone, tt.wantErr)
			}
			if tt.wantErr && tt.callErr != nil && !errors.Is(err, tt.callErr) {
				t.Errorf("error %v does not wrap native error %v", err, tt.callErr)
			}
		})
	}
}
