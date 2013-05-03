# This file is part of UnivaqLogger software.
#
# UnivaqLogger is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# UnivaqLogger is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with UnivaqLogger.  If not, see <http://www.gnu.org/licenses/>.
# 
# Copyright (C) 2013 Walter Tiberti

TEMPLATE = app
TARGET = 
DEPENDPATH += .
INCLUDEPATH += .

# Input
HEADERS += defs.h UnivaqLoggerForm.h
FORMS += interface.ui
SOURCES += UnivaqLogger_main.cpp UnivaqLoggerForm.cpp
RESOURCES += risorse.qrc
LIBS += -lssl -lcrypto