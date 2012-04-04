CPATH = ../lib/bcprov-jdk15on-147.jar:.
BLD = .
SRC = .

JAVAOPTS = -classpath $(CPATH)
JAVAC = javac

CLASSES = TransException.class \
          Account.class \
          AccountDB.class \
          AccountException.class \
          ATMCard.class \
          ATMClient.class \
          ATMSession.class \
          BankKeys.class \
          BankServer.class \
          BankSession.class \
          Crypto.class \
          Disk.class \
          KeyGen.class \
          Log.class \
          LogInterface.class \
          MakeAccounts.class \
          Message.class \
          Session.class \
          SignedMessage.class \
          ProtocolMessage.class \
          AuthInit.class \
          Challenge.class \
          Response.class \
          MakeDeposit.class \
          MakeWithdrawal.class \
          CheckBalance.class \
          Quit.class \
          TransactionResponse.class \
          LogMessage.class \
          AuthMessage.class \
          TranMessage.class \
          DumpLog.class \
          LogMessageHeader.class

.PHONY: all clean

all: $(CLASSES)

clean:
	rm -fv $(CLASSES)

%.class: %.java
	$(JAVAC) $(JAVAOPTS) $<

