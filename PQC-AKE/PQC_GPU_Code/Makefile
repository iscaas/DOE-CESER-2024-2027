###########################################################
# User-configurable
###########################################################

CUDA_ROOT_DIR ?= /usr/local/cuda-12.6

# Host compiler & flags
CC       := g++
CC_FLAGS := 
# For release builds uncomment:
# CC_FLAGS += -O3 -DNDEBUG

# NVCC & flags
NVCC       := $(CUDA_ROOT_DIR)/bin/nvcc
NVCC_FLAGS := -rdc=true -arch=sm_75 -Xptxas -v -lineinfo -g
# For release builds uncomment:
# NVCC_FLAGS += -O3 -DNDEBUG

# Neutralize dangerous macros that collide with system headers
NVCC_FLAGS += -UN -ULOGN
NVCC_FLAGS += -DAESGPU


# Pre-include the undef shim (absolute or $(PWD)/preundef.h)
NVCC_FLAGS += -include $(PWD)/preundef.h

# CUDA include/library dirs
CUDA_INC_DIR := -I$(CUDA_ROOT_DIR)/include
CUDA_LIB_DIR := -L$(CUDA_ROOT_DIR)/lib64

# Link libraries
CUDA_LINK_LIBS := -lcudart
OPENSSL_LIBS   := -lssl -lcrypto

# Project dirs
SRC_DIR := src
OBJ_DIR := bin
INC_DIR := include

# Target
EXE := run_test

###########################################################
# Sources / Objects
###########################################################

# CUDA source files in src/
CUDA_SRCS := cuda_kernel.cu fft.cu shake.cu common.cu ffSampling.cu rng.cu sha2.cu incdpa.cu poly_func.cu reduce.cu aes_gpu.cu fips2024.cu keygeneration.cu
CUDA_OBJS := $(addprefix $(OBJ_DIR)/,$(CUDA_SRCS:.cu=.o))

# Top-level TU (main); lives at project root as main.cu
MAIN_OBJ  := $(OBJ_DIR)/main.o

OBJS := $(MAIN_OBJ) $(CUDA_OBJS)

###########################################################
# Default rule
###########################################################

.PHONY: all
all: $(EXE)

###########################################################
# Build rules
###########################################################

# Link
$(EXE): $(OBJS) | $(OBJ_DIR)
	$(NVCC) $(NVCC_FLAGS) $(CUDA_LIB_DIR) -o $@ $(OBJS) $(CUDA_LINK_LIBS) $(OPENSSL_LIBS) $(CUDA_INC_DIR)

# Ensure bin exists
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile root main.cu
$(OBJ_DIR)/main.o: main.cu | $(OBJ_DIR)
	$(NVCC) $(NVCC_FLAGS) $(CUDA_INC_DIR) -I$(INC_DIR) -c $< -o $@

# Compile CUDA sources under src/
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cu $(INC_DIR)/%.cuh | $(OBJ_DIR)
	$(NVCC) $(NVCC_FLAGS) $(CUDA_INC_DIR) -I$(INC_DIR) -c $< -o $@

# (Optional) Compile C sources with matching headers
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/%.h | $(OBJ_DIR)
	$(CC) $(CC_FLAGS) -I$(INC_DIR) -c $< -o $@

###########################################################
# Housekeeping
###########################################################

.PHONY: clean
clean:
	$(RM) $(OBJ_DIR)/*.o $(EXE)
