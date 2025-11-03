package algorithm

import "fmt"

// BinarySearch implements binary search for MTU discovery
type BinarySearch struct {
	Low         int
	High        int
	Current     int
	Iterations  int
	MaxIter     int
	LastSuccess int  // Track the last successful MTU
	Converged   bool // Track if search has converged
}

// NewBinarySearch creates a new binary search instance for MTU range
func NewBinarySearch(minVal, maxVal int) *BinarySearch {
	if minVal > maxVal {
		minVal, maxVal = maxVal, minVal
	}

	return &BinarySearch{
		Low:         minVal,
		High:        maxVal,
		Current:     (minVal + maxVal) / 2,
		MaxIter:     20,         // Reasonable limit for MTU search
		LastSuccess: minVal - 1, // Initialize to below minimum
		Converged:   false,
	}
}

// Next returns the next MTU value to test
func (bs *BinarySearch) Next() int {
	if bs.IsDone() {
		return bs.GetResult()
	}
	return bs.Current
}

// Update updates the search based on probe success/failure and returns true if search is complete
func (bs *BinarySearch) Update(success bool) bool {
	bs.Iterations++

	if success {
		// MTU works, try larger values
		bs.LastSuccess = bs.Current
		bs.Low = bs.Current + 1
	} else {
		// MTU doesn't work, try smaller values
		bs.High = bs.Current - 1
	}

	// Check convergence conditions
	if bs.Low > bs.High {
		bs.Converged = true
		return true
	}

	if bs.Iterations >= bs.MaxIter {
		bs.Converged = true
		return true
	}

	// Calculate next test value
	bs.Current = (bs.Low + bs.High) / 2

	return false
}

// UpdateWithMTUHint updates search when we receive MTU hint from PMTUD response
func (bs *BinarySearch) UpdateWithMTUHint(success bool, hintMTU int) bool {
	if success {
		bs.LastSuccess = bs.Current
		bs.Low = bs.Current + 1
	} else {
		bs.High = bs.Current - 1

		// If we got an MTU hint from PMTUD, use it to narrow the search
		if hintMTU > 0 && hintMTU < bs.Current {
			bs.High = hintMTU - 1
		}
	}

	bs.Iterations++

	// Check convergence
	if bs.Low > bs.High || bs.Iterations >= bs.MaxIter {
		bs.Converged = true
		return true
	}

	bs.Current = (bs.Low + bs.High) / 2
	return false
}

// IsDone checks if the search is complete
func (bs *BinarySearch) IsDone() bool {
	return bs.Converged || bs.Low > bs.High || bs.Iterations >= bs.MaxIter
}

// GetResult returns the final MTU result (largest working MTU)
func (bs *BinarySearch) GetResult() int {
	if bs.LastSuccess > 0 {
		return bs.LastSuccess
	}
	// If no successful probe, return the lower bound
	return bs.Low - 1
}

// GetProgress returns search progress information
func (bs *BinarySearch) GetProgress() (current, low, high, iterations int, converged bool) {
	return bs.Current, bs.Low, bs.High, bs.Iterations, bs.Converged
}

// GetSearchRange returns the current search range
func (bs *BinarySearch) GetSearchRange() (int, int) {
	return bs.Low, bs.High
}

// Reset resets the search with new bounds
func (bs *BinarySearch) Reset(minVal, maxVal int) error {
	if minVal > maxVal {
		return fmt.Errorf("invalid range: min (%d) > max (%d)", minVal, maxVal)
	}

	bs.Low = minVal
	bs.High = maxVal
	bs.Current = (minVal + maxVal) / 2
	bs.Iterations = 0
	bs.LastSuccess = minVal - 1
	bs.Converged = false

	return nil
}

// HasValidResult checks if we found at least one working MTU
func (bs *BinarySearch) HasValidResult() bool {
	return bs.LastSuccess > 0
}

// GetIterationCount returns the number of iterations performed
func (bs *BinarySearch) GetIterationCount() int {
	return bs.Iterations
}
