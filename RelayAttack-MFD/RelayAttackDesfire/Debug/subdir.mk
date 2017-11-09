################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../log.c \
../mirror-subr.c \
../nfc-internal.c \
../nfc-original-reader.c \
../nfc-utils.c \
../pn53x.c 

OBJS += \
./log.o \
./mirror-subr.o \
./nfc-internal.o \
./nfc-original-reader.o \
./nfc-utils.o \
./pn53x.o 

C_DEPS += \
./log.d \
./mirror-subr.d \
./nfc-internal.d \
./nfc-original-reader.d \
./nfc-utils.d \
./pn53x.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -std=c99 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


