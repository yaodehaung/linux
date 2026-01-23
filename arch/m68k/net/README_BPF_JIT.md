# m68k BPF JIT 编译器实现总结

## 文件创建/修改清单

### 1. `arch/m68k/Kconfig` (已修改)
- 添加 `select HAVE_EBPF_JIT` 选项
- 启用m68k架构的BPF JIT支持

### 2. `arch/m68k/net/bpf_jit_comp.c` (新建)
m68k BPF JIT编译器的主要实现文件，包含：

#### a) 寄存器映射 (bpf_to_m68k_reg)
```
BPF Register  ->  m68k Register  ->  用途
R0            ->  D0             ->  返回值
R1            ->  A0             ->  第1个参数
R2            ->  A1             ->  第2个参数
R3            ->  A2             ->  第3个参数
R4            ->  A3             ->  第4个参数
R5            ->  A4             ->  第5个参数
R6            ->  D1             ->  被调用者保存
R7            ->  D2             ->  被调用者保存
R8            ->  D3             ->  被调用者保存
R9            ->  D4             ->  被调用者保存
R10 (FP)      ->  A5             ->  栈帧指针
```

#### b) 指令生成函数
已实现的m68k指令生成：
- **数据移动**: MOVE.L (32位), MOVEM (多寄存器)
- **算术运算**: ADD.L, SUB.L
- **逻辑运算**: AND.L, OR.L, EOR.L (XOR)
- **移位运算**: LSL.L (左移), LSR.L (右移), ASR.L (算术右移)
- **比较**: CMP.L
- **分支**: BEQ, BNE, BGT, BLT, BGE, BLE, JMP, RTS

#### c) 栈帧管理
- emit_prologue(): 保存被调用者保存的寄存器，建立栈帧
- emit_epilogue(): 恢复寄存器并返回

#### d) BPF指令编译
主要的bpf_jit_comp()函数实现了两遍编译：
- **第一遍**: 计算生成代码的大小
- **第二遍**: 实际生成m68k机器码

已实现的BPF操作：
- ✅ 32位ALU操作: ADD, SUB, AND, OR, XOR, LSH, RSH, ARSH
- ✅ BPF_JMP | BPF_EXIT (跳转到结束)
- ⏳ 64位ALU操作 (框架已准备，待完成)
- ⏳ 内存操作 LDX, STX, ST (框架已准备，待完成)
- ⏳ 条件分支 JEQ, JNE, JGT等 (框架已准备，待完成)
- ⏳ 辅助函数调用 CALL (框架已准备，待完成)
- ⏳ 乘法、除法、取模运算 (框架已准备，待完成)

### 3. `arch/m68k/net/Makefile` (新建)
编译配置：
```makefile
obj-$(CONFIG_BPF_JIT) += bpf_jit_comp.o
```

## 实现特点

### 1. 两遍编译设计
- 第一遍计算出需要的代码大小
- 分配内存缓冲区
- 第二遍在缓冲区中生成实际代码

### 2. 指令编码
- 大多数m68k指令是16位（2字节）
- 某些需要立即数的指令后跟32位操作数
- emit_word() 和 emit_insn() 函数分别处理16位和32位

### 3. 立即数处理
- 对于带立即数的操作，先用 MOVE.L 将立即数加载到临时寄存器(D0)
- 然后执行操作（ADD, AND, OR等）
- 这是因为m68k的许多指令不能直接使用大的立即数

### 4. 栈帧布局
```
高地址 <- 原始 A7
       | 被调用者保存的寄存器 |
       | (D1-D4, A5-A6)     |
       | BPF栈空间          |
低地址 <- 当前 A7
```

## 后续完成项

为使JIT编译器完全功能化，还需完成：

1. **64位ALU操作**: m68k是32位架构，需要用寄存器对处理64位值
2. **内存操作**: MOVE指令处理各种寻址模式和数据大小
3. **条件分支**: CMP + B条件分支的配合
4. **函数调用**: 实现BPF_JMP|BPF_CALL以调用内核辅助函数
5. **复杂运算**: 乘法(MULS)、除法(DIVS)需要专门处理
6. **错误处理**: 除以零、边界检查等

## 测试建议

基础框架完成后，可以进行：
1. 编译测试 (`make M68K_JIT=1`)
2. 简单BPF程序测试 (如返回常数)
3. 逐步增加复杂度 (ALU → 内存 → 分支 → 函数调用)

## 参考

- ARM BPF JIT: arch/arm/net/bpf_jit_32.c (2293行)
- PA-RISC BPF JIT: arch/parisc/net/bpf_jit_comp.c
- m68k指令集: Motorola M68000 Family Reference Manual
