DIRS = ./module/ ./usercommand/

TARGET_PATH = $(shell pwd)/build
export TARGET_PATH

all:
	@for dir in $(DIRS); do\
		$(MAKE) -C $$dir all;\
	done
clean:
	rm -rf $(TARGET_PATH)/*
	@for dir in $(DIRS); do\
		$(MAKE) -C $$dir clean;\
	done
