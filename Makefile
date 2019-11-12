NAME := netconfd
CHSRV := chserver
CHCLNT := chclient

CHECK_SUBDIRS := test

INCDIR := -I /usr/include/libxml2

LDFLAGS += -lnetconf

CFLAGS += $(INCDIR) -DDISABLE_NOTIFICATIONS -D_GNU_SOURCE --std=c99 -ggdb -Wall -Wextra -Werror
TEST_CFLAGS += $(INCDIR) -Wall -Wextra -Werror

SRCS := configd/configd_datastore.c configd/configd_path.c main.c

OBJS := $(SRCS:%.c=$(OBJDIR)/%.o) $(CHSRV).o

all: $(NAME) $(CHSRV) $(CHCLNT)

$(NAME): LDFLAGS += -lxml2 -lvyatta-config -levent -lvyatta-util -luriparser
$(NAME): $(SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(SRCS)

$(CHSRV): $(CHSRV).c

$(CHCLNT): $(CHCLNT).c

check:
	@for i in $(CHECK_SUBDIRS); \
	do $(MAKE) all CFLAGS=$(TEST_CFLAGS) -C $$i; done

install:
	install -D $(NAME) $(DESTDIR)/opt/vyatta/bin/$(NAME)

clean:
	$(RM) $(OBJS) $(NAME) callhome_client
