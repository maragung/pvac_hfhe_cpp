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

debug: $(BUILD)/test_main_debug
sanitize: $(BUILD)/test_main_san
examples: $(BUILD)/basic_usage

test: $(BUILD)/test_main
	@./$(BUILD)/test_main

test-v: $(BUILD)/test_main
	@PVAC_DBG=2 ./$(BUILD)/test_main

test-q: $(BUILD)/test_main
	@PVAC_DBG=0 ./$(BUILD)/test_main

test-hg: $(BUILD)/test_hg
	@./$(BUILD)/test_hg

clean:
	rm -rf $(BUILD) pvac_metrics.csv

help:
	@echo "targets: all test test-v test-q test-hg debug sanitize examples clean"
	@echo "env: PVAC_DBG=0|1|2"

.PHONY: all test test-v test-q test-hg clean help