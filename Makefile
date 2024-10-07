NAME		:= ft_nm

OBJ_DIR		:= build

LIBFT_DIR	:= libft
LIBFT_LIB	:= $(LIBFT_DIR)/libft.a

SRC_FILES	:= main.c
OBJ_FILES	:= $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))
DEP_FILES	:= $(patsubst %.c,$(OBJ_DIR)/%.d,$(SRC_FILES))

CC		:= clang

CFLAGS		:= -Wall -Wextra -MMD -MP -I$(LIBFT_DIR)/include
LFLAGS		:=

LINK_CMD	:= $(CC)

ifndef config
	config	:= debug
endif

ifeq ($(config), debug)
	CFLAGS	+= -g3 -Og -fno-inline -DNM_DEBUG
	LFLAGS	+= -g3 -Og -fno-inline
else ifeq ($(config), debug)
	CFLAGS	+= -g3 -O1 -DPING_DEBUG
	LFLAGS	+= -g3 -O1
else ifeq ($(config), distr)
	CFLAGS	+= -g0 -O3 
	LFLAGS	+= -g0 -O3 
else
$(error "$(config): unknown config")
endif

ifndef san
	san 	:= none
endif

ifeq ($(san), addr)
	CFLAGS += -fsanitize=address,undefined
	LFLAGS += -fsanitize=address,undefined
else ifeq ($(san), mem)
	CFLAGS += -fsanitize=memory,undefined -fsanitize-memory-track-origins
	LFLAGS += -fsanitize=memory,undefined -fsanitize-memory-track-origins
else ifneq ($(san), none)
$(error "$(san): unknown sanitizer config")
endif

all: $(NAME)

$(NAME): $(LIBFT_LIB) $(OBJ_FILES)
	$(LINK_CMD) -o $@ $(OBJ_FILES) $(LFLAGS) $(LIBFT_LIB)

$(LIBFT_LIB):
	${MAKE} -C $(LIBFT_DIR) config=$(config) san=$(san)

$(OBJ_DIR)/%.o: %.c Makefile
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	${MAKE} -C $(LIBFT_DIR) clean
	rm -rf $(OBJ_DIR)

fclean:
	${MAKE} -C $(LIBFT_DIR) fclean
	${MAKE} clean
	rm -f $(NAME)

re:
	${MAKE} fclean
	${MAKE}

fmt:
	clang-format -i $(SRC_FILES)

.PHONY: all clean fclean re check format
-include $(DEP_FILES)
