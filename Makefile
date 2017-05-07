NOSE3 = nosetests-3

all: check

check:
	$(NOSE3)

clean:
	rm -f *~ *.pyc *.pyo
