

.PHONY: all tests
all: tests

tests: run_tests_state_file

# state_file tests
run_tests_state_file:
	$(MAKE) -C ./state_file/ tests

clean:
	$(MAKE) -C ./state_file/ clean
