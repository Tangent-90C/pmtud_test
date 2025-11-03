package algorithm

import (
	"testing"
)

func TestNewBinarySearch(t *testing.T) {
	tests := []struct {
		name     string
		minVal   int
		maxVal   int
		expected struct {
			low     int
			high    int
			current int
		}
	}{
		{
			name:   "Normal range",
			minVal: 68,
			maxVal: 1500,
			expected: struct {
				low     int
				high    int
				current int
			}{68, 1500, 784},
		},
		{
			name:   "Swapped range (should be corrected)",
			minVal: 1500,
			maxVal: 68,
			expected: struct {
				low     int
				high    int
				current int
			}{68, 1500, 784},
		},
		{
			name:   "Single value range",
			minVal: 100,
			maxVal: 100,
			expected: struct {
				low     int
				high    int
				current int
			}{100, 100, 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := NewBinarySearch(tt.minVal, tt.maxVal)

			if bs.Low != tt.expected.low {
				t.Errorf("Expected Low=%d, got %d", tt.expected.low, bs.Low)
			}
			if bs.High != tt.expected.high {
				t.Errorf("Expected High=%d, got %d", tt.expected.high, bs.High)
			}
			if bs.Current != tt.expected.current {
				t.Errorf("Expected Current=%d, got %d", tt.expected.current, bs.Current)
			}
			if bs.Iterations != 0 {
				t.Errorf("Expected Iterations=0, got %d", bs.Iterations)
			}
			if bs.LastSuccess != tt.expected.low-1 {
				t.Errorf("Expected LastSuccess=%d, got %d", tt.expected.low-1, bs.LastSuccess)
			}
		})
	}
}

func TestBinarySearchNext(t *testing.T) {
	bs := NewBinarySearch(68, 1500)

	// First call should return the initial current value
	next := bs.Next()
	expected := 784 // (68 + 1500) / 2
	if next != expected {
		t.Errorf("Expected Next()=%d, got %d", expected, next)
	}

	// Should return same value until Update is called
	next2 := bs.Next()
	if next2 != expected {
		t.Errorf("Expected consistent Next() value, got %d", next2)
	}
}

func TestBinarySearchUpdate(t *testing.T) {
	bs := NewBinarySearch(68, 1500)

	// Test successful probe (should increase low bound)
	initialCurrent := bs.Current
	done := bs.Update(true)

	if done {
		t.Error("Search should not be done after first update")
	}
	if bs.LastSuccess != initialCurrent {
		t.Errorf("Expected LastSuccess=%d, got %d", initialCurrent, bs.LastSuccess)
	}
	if bs.Low != initialCurrent+1 {
		t.Errorf("Expected Low=%d, got %d", initialCurrent+1, bs.Low)
	}
	if bs.Iterations != 1 {
		t.Errorf("Expected Iterations=1, got %d", bs.Iterations)
	}

	// Test failed probe (should decrease high bound)
	bs2 := NewBinarySearch(68, 1500)
	initialCurrent2 := bs2.Current
	done2 := bs2.Update(false)

	if done2 {
		t.Error("Search should not be done after first update")
	}
	if bs2.High != initialCurrent2-1 {
		t.Errorf("Expected High=%d, got %d", initialCurrent2-1, bs2.High)
	}
	if bs2.LastSuccess != 67 { // Should remain at initial value (68-1)
		t.Errorf("Expected LastSuccess=67, got %d", bs2.LastSuccess)
	}
}

func TestBinarySearchConvergence(t *testing.T) {
	bs := NewBinarySearch(100, 110)

	iterations := 0
	maxIterations := 20

	// Simulate a scenario where MTU 105 works but 106 doesn't
	for !bs.IsDone() && iterations < maxIterations {
		current := bs.Next()
		success := current <= 105
		bs.Update(success)
		iterations++
	}

	if !bs.IsDone() {
		t.Error("Search should have converged")
	}

	result := bs.GetResult()
	if result != 105 {
		t.Errorf("Expected result=105, got %d", result)
	}

	if !bs.HasValidResult() {
		t.Error("Should have valid result")
	}
}

func TestBinarySearchWithMTUHint(t *testing.T) {
	bs := NewBinarySearch(68, 1500)

	// Simulate failed probe with MTU hint
	hintMTU := 1000
	done := bs.UpdateWithMTUHint(false, hintMTU)

	if done {
		t.Error("Search should not be done after first update")
	}

	// High should be set to hint MTU - 1 only if hintMTU < current
	// Initial current is 784, so hintMTU 1000 > 784, so hint is ignored
	// High should be set to current - 1 = 784 - 1 = 783
	expectedHigh := 783
	if bs.High != expectedHigh {
		t.Errorf("Expected High=%d, got %d", expectedHigh, bs.High)
	}

	// Test successful probe with hint (hint should be ignored)
	bs2 := NewBinarySearch(68, 1500)
	initialCurrent2 := bs2.Current
	bs2.UpdateWithMTUHint(true, hintMTU)

	if bs2.LastSuccess != initialCurrent2 {
		t.Errorf("Expected LastSuccess=%d, got %d", initialCurrent2, bs2.LastSuccess)
	}
	if bs2.Low != initialCurrent2+1 {
		t.Errorf("Expected Low=%d, got %d", initialCurrent2+1, bs2.Low)
	}
}

func TestBinarySearchIsDone(t *testing.T) {
	// Test convergence by bounds
	bs := NewBinarySearch(100, 100)
	bs.Update(false) // This should make Low > High
	if !bs.IsDone() {
		t.Error("Search should be done when Low > High")
	}

	// Test max iterations
	bs2 := NewBinarySearch(68, 1500)
	bs2.Iterations = bs2.MaxIter
	if !bs2.IsDone() {
		t.Error("Search should be done when max iterations reached")
	}

	// Test converged flag
	bs3 := NewBinarySearch(68, 1500)
	bs3.Converged = true
	if !bs3.IsDone() {
		t.Error("Search should be done when converged flag is set")
	}
}

func TestBinarySearchGetResult(t *testing.T) {
	// Test with successful probes
	bs := NewBinarySearch(68, 1500)
	bs.LastSuccess = 1000
	result := bs.GetResult()
	if result != 1000 {
		t.Errorf("Expected result=1000, got %d", result)
	}

	// Test with no successful probes
	bs2 := NewBinarySearch(68, 1500)
	// LastSuccess remains at initial value (67)
	result2 := bs2.GetResult()
	expected := bs2.Low - 1 // Should return 67
	if result2 != expected {
		t.Errorf("Expected result=%d, got %d", expected, result2)
	}
}

func TestBinarySearchGetProgress(t *testing.T) {
	bs := NewBinarySearch(68, 1500)
	bs.Update(true) // Make one update

	current, low, high, iterations, converged := bs.GetProgress()

	if current != bs.Current {
		t.Errorf("Expected current=%d, got %d", bs.Current, current)
	}
	if low != bs.Low {
		t.Errorf("Expected low=%d, got %d", bs.Low, low)
	}
	if high != bs.High {
		t.Errorf("Expected high=%d, got %d", bs.High, high)
	}
	if iterations != bs.Iterations {
		t.Errorf("Expected iterations=%d, got %d", bs.Iterations, iterations)
	}
	if converged != bs.Converged {
		t.Errorf("Expected converged=%v, got %v", bs.Converged, converged)
	}
}

func TestBinarySearchGetSearchRange(t *testing.T) {
	bs := NewBinarySearch(68, 1500)
	low, high := bs.GetSearchRange()

	if low != 68 {
		t.Errorf("Expected low=68, got %d", low)
	}
	if high != 1500 {
		t.Errorf("Expected high=1500, got %d", high)
	}
}

func TestBinarySearchReset(t *testing.T) {
	bs := NewBinarySearch(68, 1500)
	bs.Update(true) // Make some changes
	bs.Update(false)

	// Reset with new range
	err := bs.Reset(100, 200)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if bs.Low != 100 {
		t.Errorf("Expected Low=100, got %d", bs.Low)
	}
	if bs.High != 200 {
		t.Errorf("Expected High=200, got %d", bs.High)
	}
	if bs.Current != 150 {
		t.Errorf("Expected Current=150, got %d", bs.Current)
	}
	if bs.Iterations != 0 {
		t.Errorf("Expected Iterations=0, got %d", bs.Iterations)
	}
	if bs.LastSuccess != 99 {
		t.Errorf("Expected LastSuccess=99, got %d", bs.LastSuccess)
	}
	if bs.Converged {
		t.Error("Expected Converged=false")
	}

	// Test invalid range
	err = bs.Reset(200, 100)
	if err == nil {
		t.Error("Expected error for invalid range")
	}
}

func TestBinarySearchHasValidResult(t *testing.T) {
	bs := NewBinarySearch(68, 1500)

	// Initially LastSuccess is 67 (68-1), so HasValidResult returns true
	// This is the current implementation behavior
	if !bs.HasValidResult() {
		t.Error("HasValidResult should return true initially (LastSuccess=67 > 0)")
	}

	// After successful probe should still have valid result
	bs.Update(true)
	if !bs.HasValidResult() {
		t.Error("Should have valid result after successful probe")
	}

	// Test with range starting at 1 to get LastSuccess = 0
	bs2 := NewBinarySearch(1, 100)
	// LastSuccess should be 0 (1-1), so HasValidResult should return false
	if bs2.HasValidResult() {
		t.Error("Should not have valid result when LastSuccess=0")
	}
}

func TestBinarySearchGetIterationCount(t *testing.T) {
	bs := NewBinarySearch(68, 1500)

	if bs.GetIterationCount() != 0 {
		t.Errorf("Expected iteration count=0, got %d", bs.GetIterationCount())
	}

	bs.Update(true)
	bs.Update(false)

	if bs.GetIterationCount() != 2 {
		t.Errorf("Expected iteration count=2, got %d", bs.GetIterationCount())
	}
}

func TestBinarySearchCompleteScenario(t *testing.T) {
	// Simulate a complete MTU discovery scenario
	bs := NewBinarySearch(68, 1500)

	// Simulate that MTU 1200 is the maximum working size
	workingMTU := 1200

	for !bs.IsDone() {
		current := bs.Next()
		success := current <= workingMTU
		bs.Update(success)

		// Prevent infinite loop in case of bugs
		if bs.GetIterationCount() > 50 {
			t.Fatal("Too many iterations, possible infinite loop")
		}
	}

	result := bs.GetResult()
	if result != workingMTU {
		t.Errorf("Expected to find MTU %d, got %d", workingMTU, result)
	}

	if !bs.HasValidResult() {
		t.Error("Should have found a valid result")
	}
}
