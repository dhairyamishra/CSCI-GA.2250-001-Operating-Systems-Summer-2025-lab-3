# ---------- Lab-3  Virtual-Memory-Manager Makefile ----------
CC      = g++
CFLAGS  = -std=c++17 -Wall -Wextra -O2 -g

BIN     = memoryman                 # final executable name the grader expects
SRCS    = memoryman.cpp  # pick up every .cpp file automatically
OUTDIR  = output              # where runit.sh will save results
REFDIR  = refout              # instructor’s reference answers

.PHONY: all test grade logs runall clean

# default target ---------------------------------------------------------
all: $(BIN)

# build the simulator ----------------------------------------------------
$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

# run the full test suite ------------------------------------------------
# outputs are placed under ./output/<...>
test: $(BIN)
	@mkdir -p $(OUTDIR)
	bash runit.sh $(OUTDIR) ./$(BIN)

# grade against reference outputs ---------------------------------------
grade: test
	bash gradeit.sh $(REFDIR) $(OUTDIR)

# generate logs ----------------------------------------------------------
#   make.log    – clean rebuild + test + grade transcript
#   gradeit.log – just the gradeit console output
logs:
	(hostname; $(MAKE) clean; $(MAKE) grade 2>&1) > make.log
	bash gradeit.sh $(REFDIR) $(OUTDIR) > gradeit.log

# convenience meta-target -----------------------------------------------
runall: all test grade logs

# cleanup ---------------------------------------------------------------
clean:
	rm -f $(BIN)
	rm -rf $(OUTDIR) *.o *.d 