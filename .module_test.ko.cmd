cmd_/home/ubuntu/qemu_espt_kernel_module/module_test.ko := ld -r  -EL  -maarch64elf  --build-id  -T ./scripts/module-common.lds -T ./arch/arm64/kernel/module.lds -o /home/ubuntu/qemu_espt_kernel_module/module_test.ko /home/ubuntu/qemu_espt_kernel_module/module_test.o /home/ubuntu/qemu_espt_kernel_module/module_test.mod.o;  true