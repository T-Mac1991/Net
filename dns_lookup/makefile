
###################��Ŀ·���ͳ�������#################################
DIR=$(shell pwd)
SRC_DIR=$(DIR)
BIN_DIR=$(DIR)
INCLUDES= -I $(DIR)

##-I/usr/local/wotrus_v1/include/ 

#OBJ_NAME=libdns_lookup.a
OBJ_NAME=dns_lookup

SRC_LIB= ./$(OBJ_NAME)
SRC_INC= $(DIR)/*.h



###################OBJ�ļ���·��#######################################
EXT=cpp
SRCS=$(wildcard $(SRC_DIR)/*.$(EXT))
OBJS=$(SRCS:.cpp=.o)




CC=g++
#CFLAGS= -g -O2 -fstack-check -maccumulate-outgoing-args  -DENABLE_ECDSA=1  -DLINUX -DHAVE_PTHREAD_RWLOCK
CFLAGS=-Wall -m64 -W -O2 -fPIC -no-pie -g
LDFLAGS= -shared -fPIC



### #@echo $ (DEPS_DIR)
.PHONY: all clean rebuild
all:$(OBJS)
	#ar -r $(OBJ_NAME) $(OBJS)
	#cp -rf $(SRC_LIB) $(DEST_LIB)
	$(CC) -o $(OBJ_NAME) $(OBJS) -levent -lpthread


$(OBJS):%.o:%.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c  $< -o $@



rebuild: clean all

clean:
	rm -rf $(OBJS) $(BIN_DIR)/$(OBJ_NAME)


