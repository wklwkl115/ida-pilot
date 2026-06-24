package session

import (
	"testing"
	"time"
)

func TestReleaseInFlightRefreshesIdleDeadline(t *testing.T) {
	t.Parallel()

	sess := &Session{
		LastActivity: time.Now().Add(-time.Hour),
		Timeout:      time.Minute,
	}

	sess.AcquireInFlight()
	if !sess.HasInFlight() {
		t.Fatal("expected session to report in-flight after acquire")
	}

	sess.ReleaseInFlight()
	if sess.HasInFlight() {
		t.Fatal("expected in-flight counter to clear after release")
	}
	if sess.IsExpired() {
		t.Fatal("release should refresh idle deadline so the session is not immediately expired")
	}
}

func TestAnalysisGuardCAS(t *testing.T) {
	t.Parallel()

	sess := &Session{}
	if !sess.TryBeginAnalysis() {
		t.Fatal("first claim should succeed")
	}
	if sess.TryBeginAnalysis() {
		t.Fatal("second claim should fail while analysis is active")
	}
	if !sess.AnalysisActive() {
		t.Fatal("expected AnalysisActive to report true while claimed")
	}

	sess.EndAnalysis()
	if sess.AnalysisActive() {
		t.Fatal("expected AnalysisActive to report false after EndAnalysis")
	}
	if !sess.TryBeginAnalysis() {
		t.Fatal("claim should succeed again after release")
	}
	sess.EndAnalysis()
}
