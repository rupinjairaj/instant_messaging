JFLAGS = -g
JC = javac

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = *.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
	
server:
	java Server $(hostName) $(port) $(clients)

client:
	java Client $(clientId) $(clientHostName) $(clientPort) $(serverHostName) $(serverPort)
