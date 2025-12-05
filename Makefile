CXX := g++
CXXFLAGS := -std=c++17 -O2 -march=native -Wall -Wextra -I./include
DEBUG_FLAGS := -g -O0 -DPVAC_DEBUG
SANITIZE_FLAGS := -fsanitize=address,undefined
BUILD := build
TESTS := tests
EXAMPLES := examples

all: $(BUILD)/test_main

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_main: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_hg: $(TESTS)/test_hg.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_main_debug: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) -o $@ $<

$(BUILD)/test_main_san: $(TESTS)/test_main.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) -o $@ $

$(BUILD)/basic_usage: $(EXAMPLES)/basic_usage.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_prf: $(TESTS)/test_prf.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_ct: $(TESTS)/test_ct.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_depth: $(TESTS)/test_depth.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_sigma: $(TESTS)/test_sigma.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BUILD)/test_zero: $(TESTS)/test_zero.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $<


debug: $(BUILD)/test_main_debug
sanitize: $(BUILD)/test_main_san
examples: $(BUILD)/basic_usage
test_zero: $(BUILD)/test_zero


test: $(BUILD)/test_main
	@./$(BUILD)/test_main

test-v: $(BUILD)/test_main
	@PVAC_DBG=2 ./$(BUILD)/test_main

test-q: $(BUILD)/test_main
	@PVAC_DBG=0 ./$(BUILD)/test_main

test-hg: $(BUILD)/test_hg
	@./$(BUILD)/test_hg

test-prf: $(BUILD)/test_prf
	@./$(BUILD)/test_prf

test-ct: $(BUILD)/test_ct
	@./$(BUILD)/test_ct

test-depth: $(BUILD)/test_depth
	@./$(BUILD)/test_depth

test-sigma: $(BUILD)/test_sigma
	@./$(BUILD)/test_sigma

test-zero: $(BUILD)/test_zero
	@./$(BUILD)/test_zero

clean:
	rm -rf $(BUILD) pvac_metrics.csv

help:
	@echo "targets: all test test-v test-q test-hg debug sanitize examples clean"
	@echo "env: PVAC_DBG=0|1|2"

.PHONY: all test test-v test-q test-hg clean help