package protocol

import "fmt"

// Step performs the IO/work for one state and returns the next state.
// All the functions would be of type Step
type Step func(s *Session) (TransferState, error)

// this is the map that maps transfer states, to the actual controller functions, and those functions are of Step type
type StepTable map[TransferState]Step

// Run drives the session until StateFinished or StateError.
func Run(s *Session, steps StepTable) error {
	for {
		current := s.GetState()

		if current == StateFinished {
			return nil
		}
		if current == StateError {
			return fmt.Errorf("session is in error state")
		}

		// this is looking into the StepTable map, for this current session and this returns back a function which was mapped to this current session
		step, ok := steps[current]
		if !ok {
			return s.Fail(fmt.Errorf("no step registered for state %s", current))
		}

		// that function that we extracted from that map is begin executed, and that func since is of Step type only, that will also return a transfer state
		next, err := step(s)
		if err != nil {
			return s.Fail(fmt.Errorf("step %s failed: %w", current, err))
		}

		if err := s.Transition(next); err != nil {
			return s.Fail(err)
		}
	}
}
