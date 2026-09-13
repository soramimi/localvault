DESTDIR = $$PWD
TEMPLATE = app
TARGET = obfuscation
QT += core

HEADERS += \
	crc32.h \
	obfuscation.h
	
SOURCES += \
	obfuscation.cpp \
	main.cpp
